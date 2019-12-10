// Package saver provides the toold for saving a single flow's packets to disk.
package saver

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"sync"
	"time"

	"github.com/m-lab/go/warnonerror"

	"github.com/spf13/afero"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"

	"github.com/m-lab/go/anonymize"
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
	// If any application layer bytes were set, zero them out.
	if p.ApplicationLayer() != nil {
		c := p.ApplicationLayer().LayerContents()
		for i := 0; i < len(c); i++ {
			c[i] = 0
		}
	}
}

// prebufferWriter writes to a bytes.Buffer, until redirect() is called, then writes to the provided Writer.
// NOT THREAD SAFE.
type prebufferedWriter struct {
	buf    *bytes.Buffer
	writer io.Writer
}

func newPrebufferedWriter() prebufferedWriter {
	// Start with modest buffer that might be adequate.
	return prebufferedWriter{buf: bytes.NewBuffer(make([]byte, 0, 8192))}
}

func (pw *prebufferedWriter) Redirect(w io.Writer) error {
	if w == nil {
		return os.ErrInvalid
	}
	_, err := pw.buf.WriteTo(w)
	if err != nil {
		return err
	}
	pw.buf = nil
	pw.writer = w

	return nil
}

func (pw *prebufferedWriter) Write(p []byte) (int, error) {
	if pw.writer != nil {
		n, err := pw.writer.Write(p)
		return n, err
	}
	n, err := pw.buf.Write(p)
	return n, err
}

// UUIDEvent is passed to the saver along with an event arrival timestamp so
// that the saver can produce an appropriately-named pcap file.
type UUIDEvent struct {
	UUID      string
	Timestamp time.Time
}

func filename(dir string, e UUIDEvent) (string, string) {
	return path.Join(dir, e.Timestamp.Format("2006/01/02")), e.UUID + ".pcap.gz"
}

type statusSetter interface {
	Set(status string)
	Done()
	Get() string
}

type status struct {
	status string
	mu     sync.Mutex
}

func newStatus(beginstate string) *status {
	metrics.SaverCount.WithLabelValues(beginstate).Inc()
	return &status{status: beginstate}
}

func (s *status) Set(newstatus string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldstatus string
	oldstatus, s.status = s.status, newstatus
	metrics.SaverCount.WithLabelValues(oldstatus).Dec()
	metrics.SaverCount.WithLabelValues(newstatus).Inc()
}

func (s *status) Done() {
	s.mu.Lock()
	defer s.mu.Unlock()
	metrics.SaverCount.WithLabelValues(s.status).Dec()
	s.status = "stopped"
}

func (s *status) Get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

// TCP provides two channels to allow packets to be saved. A well-buffered
// channel for packets and a channel to receive the UUID.
type TCP struct {
	// Pchan is the channel down which pointers to packets will be sent.
	Pchan chan<- gopacket.Packet
	// UUIDChan is the channel that receives UUIDs with timestamps.
	UUIDchan chan<- UUIDEvent

	// The internal-only readable channels.
	pchanRead    <-chan gopacket.Packet
	uuidchanRead <-chan UUIDEvent

	fs     afero.Fs
	dir    string
	cancel func()
	state  statusSetter
	anon   anonymize.IPAnonymizer

	id string

	stopOnce sync.Once
}

// Increment the error counter when errors are encountered.
func (t *TCP) error(cause string) {
	t.state.Set(cause + "error")
	metrics.SaverErrors.WithLabelValues(cause).Inc()
}

// Start the process of reading the data and saving it to a file.
func (t *TCP) start(ctx context.Context, uuidDelay, duration time.Duration) {
	metrics.SaversStarted.Inc()
	defer metrics.SaversStopped.Inc()
	defer t.state.Done()

	t.savePackets(ctx, uuidDelay, duration)
	t.discardPackets(ctx)
}

// savePackets takes packet from the pchan, anonymizes them and buffers the
// resulting pcap file in RAM. Once the passed-in duration has passed, it writes
// the resulting file to disk.
func (t *TCP) savePackets(ctx context.Context, uuidDelay, duration time.Duration) {
	pw := newPrebufferedWriter()

	zip := gzip.NewWriter(&pw)

	// Write PCAP data to the buffer.
	w := pcapgo.NewWriterNanos(zip)
	// Now save packets until the stream is done or the context is canceled.
	t.state.Set("readingcandidatepackets")

	uuidCtx, uuidCancel := context.WithTimeout(ctx, uuidDelay)
	defer uuidCancel()
	// Read the first packet to determine the TCP+IP header size (as IPv6 is variable in size)
	p, ok := t.readPacket(uuidCtx)
	if !ok {
		// This error should never occur in production. It indicates a
		// configuration error or a bug in packet-headers.
		log.Println("PCAP capture cancelled with no packets for flow", t.id)
		t.error("nopackets")
		return
	}
	headerLen := len(p.Data())
	// Now we try to discover the correct header length for the flow by
	// discovering the size of everything before the transport layer, then
	// adding that size and 60 bytes for the TCP header
	// (https://en.wikipedia.org/wiki/Transmission_Control_Protocol#TCP_segment_structure).
	// IPv6 supports variable-length headers (unlike IPv4, where the length of
	// the IPv4 header is well-defined), so this is actually required as opposed
	// to just choosing the right value as a commandline parameter.
	//
	// This algorithm assumes that IPv6 header lengths are stable for a given
	// flow.
	tl := p.TransportLayer()
	if tl != nil {
		// "LayerContents" == the TCP header
		//                    (I don't know why it's not "LayerHeader")
		// "LayerPayload" == everything contained within the transport (TCP)
		// layer that is not the header (including all bytes for all subsequent
		// layers)
		//
		// So, the data we want to save is: the complete packet before the TCP
		// layer, plus the maximum size of a TCP header. We calculate this size
		// by subtracting the actual TCP header and payload lengths from the
		// overall packet size and then adding 60.
		headerLen = len(p.Data()) - len(tl.LayerContents()) - len(tl.LayerPayload()) + 60
	}
	// Write out the header and the first packet.
	w.WriteFileHeader(uint32(headerLen), layers.LinkTypeEthernet)
	t.savePacket(w, p, headerLen)

	t.state.Set("uuidwait")
	// Read packets while waiting for uuid event, or uuidCtx expires..
	// The error conditions below are expected to occur in production. In
	// particular, every flow that existed prior to the start of the start of
	// the packet-headers binary will cause this error at least once.
	//
	// This error will also occur for long-lived flows that send packets so
	// infrequently that the flow gets garbage-collected between packet
	// arrivals.
	var uuidEvent UUIDEvent
	for uuidCtx.Err() == nil {
		select {
		// If the context expires, no need to keep capturing.
		case <-uuidCtx.Done():
			log.Println("Context expired waiting for UUID for flow", t.id)
			t.error("uuidtimedout")
			return

		// Any packets should be written to the buffer.
		case p, ok := <-t.pchanRead:
			if ok {
				t.savePacket(w, p, headerLen)
			}

		// Note: if packet channel gets backed up, select algorithm may drain more packets after UUID arrives.
		case uuidEvent, ok = <-t.uuidchanRead:
			if !ok {
				// If the channel is closed, then we can never get the uuid, so stop capturing.
				log.Println("UUID channel closed, PCAP capture cancelled with no UUID for flow", t.id)
				t.error("uuidchanclosed")
				return
			}
			// Once the uuid event is received we cancel the context and exit the loop.
			t.state.Set("uuidfound")
			uuidCancel() // Exit the loop
		}
	}

	// uuidEvent is now set to a good value.
	// Create a file and directory based on the UUID and the time.
	t.state.Set("dircreation")
	dir, fname := filename(t.dir, uuidEvent)
	log.Println("Create", dir)
	err := t.fs.MkdirAll(dir, 0777)
	if err != nil {
		t.state.Set("mkdirerror")
		log.Println("Could not create directory", dir, err)
		t.error("mkdir")
		return
	}

	// Switch to file output mode, and write first part of file.
	t.state.Set("writepartial")
	fullFilename := path.Join(dir, fname)
	log.Println("Create", fname)
	file, err := t.fs.OpenFile(fullFilename, os.O_WRONLY|os.O_CREATE, 0664)
	if err != nil {
		t.error("fileopen")
		return
	}
	defer warnonerror.Close(file, fmt.Sprint("Could not close", file.Name()))

	err = pw.Redirect(file)
	if err != nil {
		t.error("writepartial")
		return
	}

	t.state.Set("streaming")

	derivedCtx, derivedCancel := context.WithTimeout(ctx, duration)
	defer derivedCancel()

	// Continue reading packets until duration has elapsed.
	for {
		p, ok := t.readPacket(derivedCtx)
		if !ok {
			break
		}
		t.savePacket(w, p, headerLen)
	}

	err = zip.Close()
	if err != nil {
		t.error("streaming")
		return
	}

	// File will be closed at end of function.
	log.Println("Successfully wrote", fullFilename, "for flow", t.id)
}

// discardPackets keeps the packet channel empty by throwing away all incoming
// packets.
func (t *TCP) discardPackets(ctx context.Context) {
	t.state.Set("discardingpackets")
	// Now read until the channel is closed or the passed-in context is cancelled.
	keepDiscarding := true
	for keepDiscarding {
		_, keepDiscarding = t.readPacket(ctx)
	}
}

func (t *TCP) readPacket(ctx context.Context) (gopacket.Packet, bool) {
	select {
	case p, ok := <-t.pchanRead:
		return p, ok
	case <-ctx.Done():
		return nil, false
	}
}

func (t *TCP) savePacket(w *pcapgo.Writer, p gopacket.Packet, headerLen int) {
	// First we make sure not to save things we should not.
	anonymizePacket(t.anon, p)

	// By design, pcaps capture packets by saving the first N bytes of each
	// packet. Because we can't be sure how big a header will be before we have
	// observed the flow, we have set N to be large and we trim packets down
	// here to not waste space when saving them to disk and to prevent any
	// privacy leaks from application layer data getting saved to .pcap files.
	//
	// CaptureInfo.CaptureLength specifies the saved length of the captured
	// packet. It is distinct from the packet length, because it is how many
	// bytes are actually returned from the pcap system, rather than how many
	// bytes the packet claims to be. The pcap system does not generate captured
	// packets with a CaptureLen larger than the packet size.
	info := p.Metadata().CaptureInfo
	info.CaptureLength = minInt(info.CaptureLength, headerLen)
	data := p.Data()
	if len(data) > headerLen {
		data = data[:headerLen]
	}
	w.WritePacket(info, data)
}

// State returns the state of the saver in a form suitable for use as a label
// value in a prometheus vector.
func (t *TCP) State() string {
	return t.state.Get()
}

// newTCP makes a new saver.TCP but does not start it. It is here as its own
// function to enable whitebox testing and instrumentation.
// fs MUST be non-null.
func newTCP(dir string, anon anonymize.IPAnonymizer, id string, fs afero.Fs) *TCP {
	// With a 1500 byte MTU, this is a ~10 millisecond buffer at a line rate of
	// 10Gbps:
	//
	//    10e9 bits/second * .01 second * 1/8 bytes/bit * 1/1500 packets/byte
	//       = 8333.3 (rounded to 8192) packets
	//
	// In the worst case, where full packets are captured, this corresponds to
	// 125KB for channel capacity and 12.5MB of actual packet data.
	//
	// If synchronization between UUID creation and packet collection is off by
	// more than 10 ms, packets may be missed. However, under load testing we
	// never observed capacity greater than 8K. Conditions that are worse than
	// load testing will have bigger problems.
	pchan := make(chan gopacket.Packet, 8192)

	// There should only ever be (at most) one write to the UUIDchan, so a
	// capacity of 1 means that the write should never block.
	uuidchan := make(chan UUIDEvent, 1)

	return &TCP{
		Pchan:     pchan,
		pchanRead: pchan,

		UUIDchan:     uuidchan,
		uuidchanRead: uuidchan,

		fs:    fs,
		dir:   dir,
		state: newStatus("notstarted"),
		anon:  anon,
		id:    id,
	}
}

// StartNew creates a new saver.TCP to save a single TCP flow and starts its
// goroutine. The goroutine can be stopped either by cancelling the passed-in
// context or by closing the Pchan channel. Closing Pchan is the preferred
// method, because it is an unambiguous signal that no more packets should be
// expected for that flow.
//
// It is the caller's responsibility to close Pchan or cancel the context.
// uuidDelay must be smaller than maxDuration.
func StartNew(ctx context.Context, anon anonymize.IPAnonymizer, dir string, uuidDelay, maxDuration time.Duration, id string) *TCP {
	s := newTCP(dir, anon, id, afero.NewOsFs())
	go s.start(ctx, uuidDelay, maxDuration)
	return s
}
