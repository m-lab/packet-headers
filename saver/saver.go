package saver

import (
	"context"
	"log"
	"os"
	"path"
	"time"

	"github.com/m-lab/packet-headers/metrics"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func filename(dir, uuid string, t time.Time) (string, string) {
	return path.Join(dir, t.Format("2006/01/02")), uuid + ".pcap"
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
// channel for packets and a channel to receive the UUID string.
type Saver struct {
	Pchan    chan gopacket.Packet
	UUIDchan chan string

	dir    string
	cancel func()
	state  statusSetter
}

// Start the process of reading the data and saving it to a file.
func (s *Saver) Start(ctx context.Context, duration time.Duration) {
	metrics.SaversStarted.Inc()
	defer metrics.SaversStopped.Inc()

	ctx, s.cancel = context.WithTimeout(ctx, duration)
	defer s.Stop()

	// First read the UUID
	s.state.Set("uuidwait")
	var uuid string
	select {
	case uuid = <-s.UUIDchan:
	case <-ctx.Done():
		log.Println("PCAP capture cancelled with no UUID")
		metrics.SaverErrors.WithLabelValues("uuid").Inc()
		s.state.Set("uuiderror")
		return
	}

	// Create a file and directory based on the UUID and the time.
	s.state.Set("filecreation")
	path, fname := filename(s.dir, uuid, time.Now())
	err := os.MkdirAll(path, 0777)
	if err != nil {
		log.Println("Could not create directory", path, err)
		metrics.SaverErrors.WithLabelValues("mkdir").Inc()
		s.state.Set("mkdirerror")
		return
	}
	f, err := os.Create(path + fname)
	if err != nil {
		log.Println("Could not create file", path, fname, err)
		metrics.SaverErrors.WithLabelValues("create").Inc()
		s.state.Set("createerror")
		return
	}
	defer f.Close()

	// Write PCAP data to the new file.
	w := pcapgo.NewWriterNanos(f)
	// TODO: find a better value than 1600
	w.WriteFileHeader(1600, layers.LinkTypeEthernet)
	// Now save packets until the stream is done or the context is canceled.
	s.state.Set("readingpackets")
	for {
		select {
		case p, ok := <-s.Pchan:
			if !ok {
				return
			}
			// TODO: zero out all non-header packet bytes
			// TODO: apply anonymization
			w.WritePacket(p.Metadata().CaptureInfo, p.Data())
		case <-ctx.Done():
			return
		}
	}
}

// Stop the saver, causing it to write its data to disk and close all open
// files. After this is called, no channel in this saver will ever be read from
// again. The saver should subsequently be allowed to pass out of scope, so that
// the garbage collector will close all open channels and reclaim all the
// resources of this saver.
func (s *Saver) Stop() {
	s.state.Set("stopped")
	if s.cancel != nil {
		s.cancel()
	}
	// Zero out the channel capacity - buffering data is foolish when it will
	// never be read.
	s.Pchan = make(chan gopacket.Packet)
}

// State returns the state of the saver in a form suitable for use as a label
// value in a prometheus vector.
func (s *Saver) State() string {
	return s.state.Get()
}

// New creates a new Saver to save a single TCP flow.
func New(dir string) *Saver {
	beginstate := "notstarted"
	metrics.SaverCount.WithLabelValues(beginstate).Inc()
	return &Saver{
		// With a 1500 byte MTU, this is a three second buffer at
		// a line rate of 10Gbps:
		// 10000000 bits/second * 3 seconds * 1/8 bytes/bit * 1/1500 packets/byte = 2500 packets
		//
		// If synchronization between UUID creation and packet
		// collection is off by more than three seconds, things are
		// messed up.
		Pchan: make(chan gopacket.Packet, 2500),

		// There should only ever be (at most) one write to the UUIDchan, so a
		// capacity of 1 means that the write should never block.
		UUIDchan: make(chan string, 1),

		dir:   dir,
		state: &status{beginstate},
	}
}
