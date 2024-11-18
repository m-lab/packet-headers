// Package demuxer contains the tools for sending packets to the right goroutine to save them to disk.
package demuxer

import (
	"context"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/m-lab/go/bytecount"

	"github.com/google/gopacket"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/packet-headers/metrics"
	"github.com/m-lab/packet-headers/saver"
	"github.com/prometheus/client_golang/prometheus"
)

// Saver allows to save data coming from this demuxer.
type Saver interface {
	PChan() chan<- gopacket.Packet
	UUIDChan() chan<- saver.UUIDEvent
	State() string
}

// A saver implementation that only drains the packet and UUID channels, to
// effectively ignore all packets and UUIDs for specific flows.
type drain struct {
	pChan    chan gopacket.Packet
	uuidChan chan saver.UUIDEvent
}

// newDrain returns a draining saver and starts a new goroutine to constantly
// drain the packet and the uuid channels until they are closed or the context
// is canceled.
func newDrain() *drain {
	// Use the same buffer size as the real saver because even if all writes to
	// these channel are non-blocking, we don't want to increase Prometheus
	// counters for failed writes in case we can't read fast enough.
	return &drain{
		pChan:    make(chan gopacket.Packet, 8192),
		uuidChan: make(chan saver.UUIDEvent, 1),
	}
}

func (d *drain) start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-d.pChan:
			if !ok {
				return
			}
		case _, ok := <-d.uuidChan:
			if !ok {
				return
			}
		}
	}
}

// PChan returns the pChan channel.
func (d *drain) PChan() chan<- gopacket.Packet {
	return d.pChan
}

// UUIDChan returns the uuidChan channel.
func (d *drain) UUIDChan() chan<- saver.UUIDEvent {
	return d.uuidChan
}

// State always returns "draining".
func (d *drain) State() string {
	return "draining"
}

// UUIDEvent is the datatype sent to a demuxer's UUIDChan to notify it about the
// UUID of new flows.
type UUIDEvent struct {
	saver.UUIDEvent
	Flow FlowKey
}

// TCP sends each received TCP/IP packet to the proper saver. If the packet
// is not a TCP/IP packet, then the demuxer will drop it.
//
// Note for those editing this code: demuxer.TCP methods are NOT threadsafe to
// avoid needing a lock in the main packet processing loop.
type TCP struct {
	UUIDChan     chan<- UUIDEvent
	uuidReadChan <-chan UUIDEvent

	// We use a generational GC. Every time the GC timer advances, we garbage
	// collect all savers in oldFlows and make all the currentFlows into
	// oldFlows. It is only through this garbage collection process that
	// saver.TCP objects are finalized.
	currentFlows map[FlowKey]Saver
	oldFlows     map[FlowKey]Saver
	drainSaver   *drain
	maxIdleRAM   bytecount.ByteCount
	status       status

	// Variables required for the construction of new Savers
	maxDuration      time.Duration
	uuidWaitDuration time.Duration
	anon             anonymize.IPAnonymizer
	dataDir          string
	stream           bool
	maxHeap          uint64
}

type status interface {
	GC(stillPresent, discarded int)
}

type promStatus struct{}

func (promStatus) GC(stillPresent, discarded int) {
	metrics.DemuxerGarbageCollected.Add(float64(discarded))
	metrics.DemuxerSaverCount.Set(float64(stillPresent))
}

func currentHeapAboveThreshold(maxHeap uint64) bool {
	ms := runtime.MemStats{}
	runtime.ReadMemStats(&ms)
	return (ms.HeapAlloc > maxHeap)
}

// GetSaver returns a saver with channels for packets and a uuid.
func (d *TCP) getSaver(ctx context.Context, flow FlowKey) Saver {
	// Read the flow from the flows map, the oldFlows map, or create it.
	t, ok := d.currentFlows[flow]
	if !ok {
		// Either move the saver from oldFlows to currentFlows, or create a new
		// one and put it in currentFlows.
		t, ok = d.oldFlows[flow]
		if ok {
			delete(d.oldFlows, flow)
		} else {

			// Only create a new Saver if we are below the configured maxHeap
			// threshold. This condition is required because a SYN flood can
			// cause packet-headers to allocate memory faster than partial
			// connection timeouts allow the garbage collector to recover used
			// memory. The result in that case would be system RAM exhaustion.
			//
			// NOTE: When we are above the maxHeap threshold, we may lose some
			// legitimate measurements. This check is a load shedding strategy
			// to keep the process running and prevent resource usage from
			// packet-headers spilling over into other parts of the system.
			if currentHeapAboveThreshold(d.maxHeap) {
				metrics.SaversSkipped.Inc()
				return d.drainSaver
			}

			// If the number of current flows exceeds the configured threshold, do not
			// create a new Saver and return drainSaver instead.
			if len(d.currentFlows) > 100 {
				metrics.DemuxerIgnoredCount.Inc()
				return d.drainSaver
			}

			t = saver.StartNew(ctx, d.anon, d.dataDir, d.uuidWaitDuration, d.maxDuration, flow.Format(d.anon), d.stream)
		}
		d.currentFlows[flow] = t
	}

	// Whether it was retrieved or created, return the saver.TCP.
	return t
}

// savePacket saves a packet to the appropriate saver.TCP
func (d *TCP) savePacket(ctx context.Context, packet gopacket.Packet) {
	if packet == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		metrics.DemuxerBadPacket.Inc()
		return
	}
	// Send the packet to the saver.
	s := d.getSaver(ctx, fromPacket(packet))
	if s == nil {
		metrics.MissedPackets.WithLabelValues("skipped").Inc()
		return
	}

	// Don't block on channel write to the saver, but do note when it fails.
	select {
	case s.PChan() <- packet:
	default:
		metrics.MissedPackets.WithLabelValues(s.State()).Inc()
	}
}

func (d *TCP) assignUUID(ctx context.Context, ev UUIDEvent) {
	metrics.DemuxerUUIDCount.Inc()
	s := d.getSaver(ctx, ev.Flow)
	if s == nil {
		metrics.MissedUUIDs.WithLabelValues("skipped").Inc()
		return
	}
	select {
	case s.UUIDChan() <- ev.UUIDEvent:
	default:
		metrics.MissedUUIDs.WithLabelValues(s.State()).Inc()
	}
}

func (d *TCP) collectGarbage() {
	timer := prometheus.NewTimer(metrics.DemuxerGCLatency)
	defer timer.ObserveDuration()

	// Collect garbage in a separate goroutine.
	go func(toBeDeleted map[FlowKey]Saver) {
		for _, s := range toBeDeleted {
			close(s.UUIDChan())
			close(s.PChan())
		}
		// Tell the VM to try and return RAM to the OS.
		ms := runtime.MemStats{}
		runtime.ReadMemStats(&ms)
		if ms.HeapIdle > uint64(d.maxIdleRAM) {
			debug.FreeOSMemory()
		}
	}(d.oldFlows)
	// Record GC data.
	d.status.GC(len(d.currentFlows), len(d.oldFlows))
	// Advance the generation.
	d.oldFlows = d.currentFlows
	d.currentFlows = make(map[FlowKey]Saver)
}

// CapturePackets captures the packets from the channel `packets` and hands them
// off to the appropriate saver.TCP object. We can never be entirely sure that a
// flow will receive no more packets - even the "socket closed" signal from the
// kernel doesn't mean there will be no more packets. Therefore, we pass in a
// ticker for garbage collection (`gcTicker`), and when that ticker has fired
// twice without a flow receiving a packet, then that flow is assumed to be
// stopped.
//
// This function can be stopped by cancelling the passed-in context or by
// closing both the passed-in packet channel and the UUIDChan to indicate that
// no future input is possible.
func (d *TCP) CapturePackets(ctx context.Context, packets <-chan gopacket.Packet, gcTicker <-chan time.Time) {
	// Start the drain goroutine.
	d.drainSaver = newDrain()
	go d.drainSaver.start(ctx)

	// This is the loop that has to run at high speed. All processing that can
	// happen outside this loop should happen outside this loop. No function
	// called from this loop should ever block.
	var ev UUIDEvent
	for {
		select {
		case packet := <-packets:
			// Get a packet and save it.
			d.savePacket(ctx, packet)
		case ev = <-d.uuidReadChan:
			// We are being told about a new uuid
			d.assignUUID(ctx, ev)
		case <-gcTicker:
			// Time to advance the generational garbage collector.
			d.collectGarbage()
		case <-ctx.Done():
			// Context is cancelled.
			return
		}
	}
}

// NewTCP creates a demuxer.TCP, which is the system which chooses which channel
// to send TCP/IP packets for subsequent saving to a file.
func NewTCP(anon anonymize.IPAnonymizer, dataDir string, uuidWaitDuration, maxFlowDuration time.Duration, maxIdleRAM bytecount.ByteCount, stream bool, maxHeap uint64) *TCP {
	uuidc := make(chan UUIDEvent, 100)
	return &TCP{
		UUIDChan:     uuidc,
		uuidReadChan: uuidc,

		currentFlows: make(map[FlowKey]Saver),
		oldFlows:     make(map[FlowKey]Saver),
		maxIdleRAM:   maxIdleRAM,
		status:       promStatus{},

		anon:             anon,
		dataDir:          dataDir,
		maxDuration:      maxFlowDuration,
		uuidWaitDuration: uuidWaitDuration,
		stream:           stream,
		maxHeap:          maxHeap,
	}
}
