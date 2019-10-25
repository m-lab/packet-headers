package saver

import (
	"context"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/m-lab/go/anonymize"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/m-lab/packet-headers/metrics"
)

// A nice example of why go generics might be nice sometimes.
func minInt(x, y int) int {
	if x <= y {
		return x
	}
	return y
}

// anonymize a packet by modifying its contained IP addresses in-place.
func anonymizePacket(a anonymize.IPAnonymizer, p gopacket.Packet) {
	if p == nil || a == nil {
		log.Println("Null packet or anonymizer. Can not anonymizePacket")
		return
	}
	nl := p.NetworkLayer()
	if nl == nil {
		log.Println("Packets with no network layers should never make it here")
		return
	}
	switch nl.LayerType() {
	case layers.LayerTypeIPv4:
		a.IP(nl.(*layers.IPv4).SrcIP)
		a.IP(nl.(*layers.IPv4).DstIP)
	case layers.LayerTypeIPv6:
		a.IP(nl.(*layers.IPv6).SrcIP)
		a.IP(nl.(*layers.IPv6).DstIP)
	}
}

// UUIDEvent is passed to the saver along with an event arrival timestamp so
// that the saver can produce an appropriately-named pcap file.
type UUIDEvent struct {
	UUID      string
	Timestamp time.Time
}

func filename(dir string, e UUIDEvent) (string, string) {
	return path.Join(dir, e.Timestamp.Format("2006/01/02")), e.UUID + ".pcap"
}

type statusSetter interface {
	Set(status string)
	Done()
	Get() string
}

type status struct {
	status string
}

func newStatus(beginstate string) *status {
	metrics.SaverCount.WithLabelValues(beginstate).Inc()
	return &status{beginstate}
}

func (s *status) Set(newstatus string) {
	var oldstatus string
	oldstatus, s.status = s.status, newstatus
	metrics.SaverCount.WithLabelValues(oldstatus).Dec()
	metrics.SaverCount.WithLabelValues(newstatus).Inc()
}

func (s *status) Done() {
	s.status = "stopped"
	metrics.SaverCount.WithLabelValues(s.status).Dec()
}

func (s *status) Get() string {
	return s.status
}

// Saver provides two channels to allow packets to be saved. A well-buffered
// channel for packets and a channel to receive the UUID.
type Saver struct {
	// Pchan is the channel down which pointers to packets will be sent.
	Pchan chan<- gopacket.Packet
	// UUIDChan is the channel that receives UUIDs with timestamps.
	UUIDchan chan<- UUIDEvent

	// The internal-only readable channels.
	pchanRead    <-chan gopacket.Packet
	uuidchanRead <-chan UUIDEvent

	dir    string
	cancel func()
	state  statusSetter
	anon   anonymize.IPAnonymizer

	stopOnce sync.Once
}

// Increment the error counter when errors are encountered.
func (s *Saver) error(cause string) {
	s.state.Set(cause + "error")
	metrics.SaverErrors.WithLabelValues(cause).Inc()
}

// Start the process of reading the data and saving it to a file.
func (s *Saver) start(ctx context.Context, duration time.Duration) {
	metrics.SaversStarted.Inc()
	defer metrics.SaversStopped.Inc()
	defer s.state.Done()

	derivedCtx, derivedCancel := context.WithTimeout(ctx, duration)
	defer derivedCancel()

	// First read the UUID
	s.state.Set("uuidwait")
	var uuidEvent UUIDEvent
	select {
	case uuidEvent = <-s.uuidchanRead:
	case <-ctx.Done():
		log.Println("PCAP capture cancelled with no UUID")
		s.error("uuid")
		return
	}

	// Create a file and directory based on the UUID and the time.
	s.state.Set("filecreation")
	dir, fname := filename(s.dir, uuidEvent)
	err := os.MkdirAll(dir, 0777)
	if err != nil {
		log.Println("Could not create directory", dir, err)
		s.error("mkdir")
		return
	}
	f, err := os.Create(path.Join(dir, fname))
	if err != nil {
		s.error("create")
		return
	}
	defer f.Close()

	// Write PCAP data to the new file.
	w := pcapgo.NewWriterNanos(f)
	// Now save packets until the stream is done or the context is canceled.
	s.state.Set("readingpackets")
	// Read the first packet to determine the TCP+IP header size (as IPv6 is variable in size)
	p, ok := s.readPacket(derivedCtx)
	if !ok {
		s.error("nopackets")
		return
	}
	headerLen := len(p.Data())
	// Now we try to discover the correct header length for the flow by
	// discovering the size of the application layer and then subtracting it
	// from the overall size of the packet data. IPv6 supports variable-length
	// headers (unlike IPv4, where the length of the IPv4 header is
	// well-defined), so this is actually required.
	//
	// This algorithm assumes that IPv6 header lengths are stable for a given
	// flow.
	al := p.ApplicationLayer()
	if al != nil {
		alSize := len(al.LayerContents())
		headerLen -= alSize
	}
	// Write out the header and the first packet.
	w.WriteFileHeader(uint32(headerLen), layers.LinkTypeEthernet)
	s.savePacket(w, p, headerLen)
	for {
		p, ok := s.readPacket(derivedCtx)
		if ok {
			s.savePacket(w, p, headerLen)
		} else {
			break
		}
	}
	f.Close()
	s.state.Set("discardingpackets")
	// Now read until the channel is closed or the passed-in context is cancelled.
	keepDiscarding := true
	for keepDiscarding {
		_, keepDiscarding = s.readPacket(derivedCtx)
	}
}

func (s *Saver) readPacket(ctx context.Context) (gopacket.Packet, bool) {
	select {
	case p, ok := <-s.pchanRead:
		return p, ok
	case <-ctx.Done():
		return nil, false
	}
}

func (s *Saver) savePacket(w *pcapgo.Writer, p gopacket.Packet, headerLen int) {
	// First we make sure not to save things we should not.
	anonymizePacket(s.anon, p)

	// By design, pcaps capture packets by saving the first N bytes of each
	// packet. Because we can't be sure how big a header will be before we have
	// observed the flow, we have set N to be large and we trim packets down
	// here to not waste space when saving them to disk.
	//
	// CaptureInfo.CaptureLength specifies the saved length of the captured
	// packet. It is distinct from the packet length, because it is how many
	// bytes are actully saved in the data returned from the pcap system, rather
	// than how many bytes the packet claims to be. The pcap system does not
	// generate captured packets with a CaptureLen larger than the packet size.
	info := p.Metadata().CaptureInfo
	info.CaptureLength = minInt(info.CaptureLength, headerLen)
	w.WritePacket(info, p.Data()[:headerLen])
}

// State returns the state of the saver in a form suitable for use as a label
// value in a prometheus vector.
func (s *Saver) State() string {
	return s.state.Get()
}

// newSaver makes a new Saver but does not start it. It is here as its own
// function to enable whitebox testing and instrumentation.
func newSaver(dir string, anon anonymize.IPAnonymizer) *Saver {
	// With a 1500 byte MTU, this is a ~1 second buffer at a line rate of 10Gbps:
	// 10e9 bits/second * 1 second * 1/8 bytes/bit * 1/1500 packets/byte = 833333.3 packets
	//
	// If synchronization between UUID creation and packet collection is off by
	// more than a second, things are messed up.
	pchan := make(chan gopacket.Packet, 833333)

	// There should only ever be (at most) one write to the UUIDchan, so a
	// capacity of 1 means that the write should never block.
	uuidchan := make(chan UUIDEvent, 1)

	return &Saver{
		Pchan:     pchan,
		pchanRead: pchan,

		UUIDchan:     uuidchan,
		uuidchanRead: uuidchan,

		dir:   dir,
		state: newStatus("notstarted"),
		anon:  anon,
	}
}

// StartNew creates a new Saver to save a single TCP flow and starts its
// goroutine. A saver's goroutine can be stopped either by cancelling the
// passed-in context or by closing the Pchan channel. Closing Pchan is the
// preferred method, because it is an unambiguous signal that no more packets
// should be expected for that flow.
func StartNew(ctx context.Context, anon anonymize.IPAnonymizer, dir string, maxDuration time.Duration) *Saver {
	s := newSaver(dir, anon)
	go s.start(ctx, maxDuration)
	return s
}
