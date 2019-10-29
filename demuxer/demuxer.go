package demuxer

import (
	"context"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/packet-headers/metrics"
	"github.com/m-lab/packet-headers/saver"
	"github.com/prometheus/client_golang/prometheus"
)

// FullFlow characterizes a TCP/IP flow without judgement about what direction
// the flow is. The lexicographically lowest IP/Port combination should always
// be first.
type FullFlow struct {
	lo, hi   string
	loP, hiP uint16
}

// fromPacket converts a packet's TCP 4-tuple into a FullFlow suitable for being
// a map key. Never pass fromPacket a non-TCP/IP packet - it will crash.
func fromPacket(p gopacket.Packet) FullFlow {
	nl := p.NetworkLayer()
	var ip1, ip2 string
	switch nl.LayerType() {
	case layers.LayerTypeIPv4:
		ip1 = string(nl.(*layers.IPv4).SrcIP)
		ip2 = string(nl.(*layers.IPv4).DstIP)
	case layers.LayerTypeIPv6:
		ip1 = string(nl.(*layers.IPv6).SrcIP)
		ip2 = string(nl.(*layers.IPv6).DstIP)
	}
	f := p.TransportLayer().(*layers.TCP)
	ip1P := uint16(f.SrcPort)
	ip2P := uint16(f.DstPort)
	if ip1 < ip2 || (ip1 == ip2 && ip1P < ip2P) {
		return FullFlow{ip1, ip2, ip1P, ip2P}
	}
	return FullFlow{ip2, ip1, ip2P, ip1P}
}

// UUIDEvent is the datatype sent to a demuxer's UUIDChan to notify it about the
// UUID of new flows.
type UUIDEvent struct {
	saver.UUIDEvent
	Flow FullFlow
}

// Demuxer sends each received TCP/IP packet to the proper saver. If the packet
// is not a TCP/IP packet, then the demuxer will drop it.
//
// Note for those editing this code: Demuxer methods are NOT threadsafe to avoid
// needing a lock in the main packet processing loop.
type Demuxer struct {
	UUIDChan     chan<- UUIDEvent
	uuidReadChan <-chan UUIDEvent

	// We use a generational GC. Every time the GC timer advances, we garbage
	// collect all savers in oldFlows and make all the currentFlows into
	// oldFlows. It is only through this garbage collection process that
	// connections are closed.
	currentFlows map[FullFlow]*saver.TCP
	oldFlows     map[FullFlow]*saver.TCP

	// Variables required for the construction of new Savers
	maxDuration time.Duration
	anon        anonymize.IPAnonymizer
	dataDir     string
}

// GetSaver returns a saver with channels for packets and a uuid.
func (d *Demuxer) getSaver(ctx context.Context, flow FullFlow) *saver.TCP {
	// Read the flow from the flows map, the oldFlows map, or create it.
	t, ok := d.currentFlows[flow]
	if !ok {
		// Either move the saver from oldFlows to currentFlows, or create a new
		// one and put it in currentFlows.
		t, ok = d.oldFlows[flow]
		if ok {
			delete(d.oldFlows, flow)
		} else {
			t = saver.StartNew(ctx, d.anon, d.dataDir, d.maxDuration)
		}
		d.currentFlows[flow] = t
	}

	// Whether it was retrieved or created, return the saver.TCP.
	return t
}

// savePacket saves a packet to the appropriate saver.TCP
func (d *Demuxer) savePacket(ctx context.Context, packet gopacket.Packet) {
	if packet == nil || packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		metrics.DemuxerBadPacket.Inc()
		return
	}
	// Send the packet to the saver.
	s := d.getSaver(ctx, fromPacket(packet))

	// Don't block on channel write to the saver, but do note when it fails.
	select {
	case s.Pchan <- packet:
	default:
		metrics.MissedPackets.WithLabelValues(s.State()).Inc()
	}
}

func (d *Demuxer) sendUUID(ctx context.Context, ev UUIDEvent) {
	metrics.DemuxerUUIDCount.Inc()
	s := d.getSaver(ctx, ev.Flow)
	select {
	case s.UUIDchan <- ev.UUIDEvent:
	default:
		metrics.MissedUUIDs.WithLabelValues(s.State()).Inc()
	}
}

func (d *Demuxer) collectGarbage() {
	timer := prometheus.NewTimer(metrics.DemuxerGCLatency)
	defer timer.ObserveDuration()

	// Collect garbage in a separate goroutine.
	go func(toBeDeleted map[FullFlow]*saver.TCP) {
		for _, s := range toBeDeleted {
			close(s.UUIDchan)
			close(s.Pchan)
		}
	}(d.oldFlows)
	// Advance the generation.
	d.oldFlows = d.currentFlows
	d.currentFlows = make(map[FullFlow]*saver.TCP)
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
func (d *Demuxer) CapturePackets(ctx context.Context, packets <-chan gopacket.Packet, gcTicker <-chan time.Time) {
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
			// We are being about a new uuid
			d.sendUUID(ctx, ev)
		case <-gcTicker:
			// Time to advance the generational garbage collector.
			d.collectGarbage()
		case <-ctx.Done():
			// Context is cancelled.
			return
		}
	}
}

// New creates a Demuxer, which is the system which chooses which channel to
// send the packets to for subsequent saving to a file.
func New(anon anonymize.IPAnonymizer, dataDir string, maxFlowDuration time.Duration) *Demuxer {
	uuidc := make(chan UUIDEvent, 100)
	return &Demuxer{
		UUIDChan:     uuidc,
		uuidReadChan: uuidc,

		currentFlows: make(map[FullFlow]*saver.TCP),
		oldFlows:     make(map[FullFlow]*saver.TCP),

		anon:        anon,
		dataDir:     dataDir,
		maxDuration: maxFlowDuration,
	}
}
