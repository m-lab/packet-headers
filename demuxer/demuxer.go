package demuxer

import (
	"context"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/packet-headers/metrics"
	"github.com/m-lab/packet-headers/saver"
)

// FullFlow characterizes a TCP/IP flow using precisely the layer values that
// gopacket says are the right ones to use for hashing.
type FullFlow struct {
	IPFlow, TCPFlow gopacket.Flow
}

// Demuxer sends each received packet to the proper saver. All methods are
// threadsafe.
type Demuxer struct {
	mutex sync.RWMutex
	flows map[FullFlow]*saver.TCP

	// Variables required for the construction of new Savers
	maxDuration time.Duration
	anon        anonymize.IPAnonymizer
	dataDir     string
}

// Close a connection, stopping its packet saving process entirely.
func (d *Demuxer) Close(flow FullFlow) {
	d.mutex.Lock()
	t, ok := d.flows[flow]
	if ok {
		delete(d.flows, flow)
	}
	d.mutex.Unlock()

	if ok {
		close(t.Pchan)
	}
}

// GetSaver returns a saver with a channel that can accept packets or uuids.
func (d *Demuxer) GetSaver(ctx context.Context, flow FullFlow) *saver.TCP {
	// Quickly read the struct and (usually) retrieve the Saver found there.
	d.mutex.RLock()
	t, ok := d.flows[flow]
	d.mutex.RUnlock()

	// The common case is to not need to do this block. The surrounding function
	// gets called for every packet, but this block of code only needs to
	// execute when a new flow appears. So we make the uncommon case slower in
	// an effort to unblock the common case. We also have to double-check the
	// condition after we re-acquire the read lock as a write lock.
	if !ok {
		// Acquire the write lock.
		d.mutex.Lock()
		t, ok = d.flows[flow]
		// Double-check the condition.
		if !ok {
			t = saver.StartNew(ctx, d.anon, d.dataDir, d.maxDuration)
			d.flows[flow] = t
		}
		// Release the write lock.
		d.mutex.Unlock()
	}

	// Whether it was retrieved or created, return the saver.TCP.
	return t
}

// PacketSource is the interface we need from the gopacket.PacketSource struct.
// We break it into an interface here to aid in testing.
type PacketSource interface {
	Packets() chan gopacket.Packet
}

// CapturePackets captures the packets and hands them off to the appropriate
// saver.TCP object.
func (d *Demuxer) CapturePackets(ctx context.Context, source PacketSource) {
	// This is the loop that has to run at high speed. All processing that can
	// happen outside this loop should happen outside this loop. This loop's
	// sole job is to keep up with the packet arrival rate and hand each packet
	// off to a goroutine. It should never block except to wait for new packet
	// from the packet source.
	for packet := range source.Packets() {
		s := d.GetSaver(ctx, FullFlow{
			IPFlow:  packet.NetworkLayer().NetworkFlow(),
			TCPFlow: packet.TransportLayer().TransportFlow(),
		})

		// Don't block on channel write to the saver, but do note when it fails.
		select {
		case s.Pchan <- packet:
		default:
			metrics.MissedPackets.WithLabelValues(s.State()).Inc()
		}
	}
}

// New creates a Demuxer, which is the system which chooses which channel to
// send the packets to for subsequent saving to a file.
func New(anon anonymize.IPAnonymizer, dataDir string, maxFlowDuration time.Duration) *Demuxer {
	return &Demuxer{
		flows: make(map[FullFlow]*saver.TCP),

		anon:        anon,
		dataDir:     dataDir,
		maxDuration: maxFlowDuration,
	}
}
