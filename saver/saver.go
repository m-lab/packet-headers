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
	case ((*layers.IPv4)(nil)).LayerType():
		a.IP(nl.(*layers.IPv4).SrcIP)
		a.IP(nl.(*layers.IPv4).DstIP)
	case ((*layers.IPv6)(nil)).LayerType():
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
	Get() string
}

type status struct {
	status string
}

func (s *status) Set(newstatus string) {
	var oldstatus string
	oldstatus, s.status = s.status, newstatus
	metrics.SaverCount.WithLabelValues(oldstatus).Dec()
	metrics.SaverCount.WithLabelValues(newstatus).Inc()
}

func (s *status) Get() string {
	return s.status
}

// Saver provides two channels to allow packets to be saved. A well-buffered
// channel for packets and a channel to receive the UUID.
type Saver struct {
	// Pchan is the channel down which pointers to packets will be sent. No
	// client should ever perform a blocking write to this channel, and if a
	// client holds onto the channel for longer than a millisecond, it risks the
	// channel being closed out from underneath it. Nothing that uses the Pchan
	// channel of a Saver should hold onto that channel for longer than it takes
	// to attempt to write a single record.
	Pchan    chan<- gopacket.Packet
	UUIDchan chan<- UUIDEvent

	// The internal-only readable channels. Until the Saver is stopped, the
	// Pchan write channel is connected to the Pchan channel. After things are
	// stopped, that connection is broken.
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
	defer s.state.Set("stopped")

	ctx, s.cancel = context.WithTimeout(ctx, duration)
	defer s.cancel()
	go func() {
		<-ctx.Done()
		s.Stop()
	}()

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
	p, ok := <-s.pchanRead
	if !ok {
		s.error("nopackets")
		return
	}
	headerLen := len(p.Data())
	// Now we try to discover the correct header length for the flow by
	// discovering the size of the application layer and then subtracting it
	// from the overall size of the packet data. IPv6 supports variable-length
	// headers, so this is actually required.
	al := p.ApplicationLayer()
	if al != nil {
		alSize := len(al.LayerContents())
		headerLen -= alSize
	}
	// Write out the header and the first packet.
	w.WriteFileHeader(uint32(headerLen), layers.LinkTypeEthernet)
	s.savePacket(w, p, headerLen)
	for p := range s.pchanRead {
		s.savePacket(w, p, headerLen)
	}
}

func (s *Saver) savePacket(w *pcapgo.Writer, p gopacket.Packet, headerLen int) {
	info := p.Metadata().CaptureInfo
	info.CaptureLength = minInt(info.CaptureLength, headerLen)
	anonymizePacket(s.anon, p)
	w.WritePacket(info, p.Data()[:headerLen])
}

// Stop the saver, causing it to write its data to disk and close all open
// files. After this is called, no channel in this saver will ever be read from
// again. The saver should subsequently be allowed to pass out of scope, so that
// the garbage collector will close all open channels and reclaim all the
// resources of this saver.
func (s *Saver) Stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		oldchan := s.Pchan
		// All future writes should go to a channel that has no capacity and will
		// never be read from.
		s.Pchan = make(chan gopacket.Packet)
		go func() {
			// Lose all race conditions, because saver requires that nobody hold
			// onto the Pchan channel for more than a millisecond.
			time.Sleep(time.Millisecond)

			// Tell the packet channel that the currently buffered data is all there
			// will ever be.
			close(oldchan)
		}()
	})
}

// State returns the state of the saver in a form suitable for use as a label
// value in a prometheus vector.
func (s *Saver) State() string {
	return s.state.Get()
}

// newSaver makes a new Saver but does not start it. It is here as its own
// function to enable whitebox testing and instrumentation.
func newSaver(dir string, anon anonymize.IPAnonymizer) *Saver {
	beginstate := "notstarted"
	metrics.SaverCount.WithLabelValues(beginstate).Inc()

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
		state: &status{beginstate},
		anon:  anon,
	}
}

// StartNew creates a new Saver to save a single TCP flow and starts its goroutine.
func StartNew(ctx context.Context, anon anonymize.IPAnonymizer, dir string, maxDuration time.Duration) *Saver {
	s := newSaver(dir, anon)
	go s.start(ctx, maxDuration)
	return s
}
