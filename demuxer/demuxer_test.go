package demuxer

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/packet-headers/saver"
)

type fakePacketSource struct {
	packets []gopacket.Packet
	c       chan gopacket.Packet
}

func (f *fakePacketSource) run() {
	if f.packets != nil {
		for _, p := range f.packets {
			log.Println("Sending packet", p)
			f.c <- p
		}
	}
}

func TestDemuxerDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestDemuxerDryRun")
	rtx.Must(err, "Could not create directory")
	defer os.RemoveAll(dir)

	d := New(anonymize.New(anonymize.None), dir, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	cancel()

	d.savePacket(ctx, nil) // No crash == success

	pChan := make(chan gopacket.Packet)
	gcTimer := make(chan time.Time)
	d.CapturePackets(ctx, pChan, gcTimer)
	close(gcTimer)
	close(pChan)
	// Does not run forever or crash == success
}

func TestDemuxerWithRealPcaps(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestDemuxerWithRealPcaps")
	rtx.Must(err, "Could not create directory")
	defer os.RemoveAll(dir)

	d := New(anonymize.New(anonymize.None), dir, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pChan := make(chan gopacket.Packet)

	wg := sync.WaitGroup{}
	wg.Add(1)
	gc := make(chan time.Time)
	// Run the demuxer and send it events.
	go func() {
		d.CapturePackets(ctx, pChan, gc)
		wg.Done()
	}()

	// Get packets from a wireshark-produced pcap file.
	handle, err := pcap.OpenOffline("../testdata/v4.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var f1, f2 FullFlow
	f1packets := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		f1 = fromPacket(p)
		f1packets = append(f1packets, p)
	}

	handle, err = pcap.OpenOffline("../testdata/v6.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {
		f2 = fromPacket(p)
		pChan <- p
	}

	d.UUIDChan <- UUIDEvent{
		UUIDEvent: saver.UUIDEvent{
			UUID:      "flow1",
			Timestamp: time.Date(2013, time.October, 31, 1, 2, 3, 4, time.UTC),
		},
		Flow: f1,
	}
	pChan <- f1packets[0]
	pChan <- f1packets[1]

	d.UUIDChan <- UUIDEvent{
		UUIDEvent: saver.UUIDEvent{
			UUID:      "flow2",
			Timestamp: time.Date(2013, time.October, 30, 1, 2, 3, 4, time.UTC),
		},
		Flow: f2,
	}

	// Busy-wait until both files appear on disk.
	var err1, err2 error
	err1 = errors.New("start out with an error")
	for err1 != nil || err2 != nil {
		_, err1 = os.Stat(dir + "/2013/10/31/flow1.pcap")
		_, err2 = os.Stat(dir + "/2013/10/30/flow2.pcap")
		log.Println(err1, err2)
	}

	// Lose all race conditions, then fire the GC to
	// cause the flows to become oldFlows.
	time.Sleep(100 * time.Millisecond)
	gc <- time.Now()
	// Send a bunch of packets to cause one of the flows to become a newflow.
	for _, p := range f1packets[2:] {
		pChan <- p
	}
	// Lose all race conditions, then fire the GC to cause one flows to become
	// an oldFlows and the other to be garbage collected.
	time.Sleep(100 * time.Millisecond)
	gc <- time.Now()
	time.Sleep(100 * time.Millisecond)
	// Verify that one flow was garbage collected.
	if len(d.oldFlows) != 1 || len(d.currentFlows) != 0 {
		t.Errorf("Should have 1 old flow, not %d and 0 currentFlows not %d", len(d.oldFlows), len(d.currentFlows))
	}
	time.Sleep(100 * time.Millisecond)
	cancel()

	wg.Wait()

	// Verify the files' contents.
	handle, err = pcap.OpenOffline(dir + "/2013/10/31/flow1.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	v4 := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		v4 = append(v4, p)
	}
	if len(v4) != 12 {
		t.Errorf("%+v should have length 12 not %d", v4, len(v4))
	}

	handle, err = pcap.OpenOffline(dir + "/2013/10/30/flow2.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	v6 := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		v6 = append(v6, p)
	}
	if len(v6) != 8 {
		t.Errorf("%+v should have length 8 not %d", v6, len(v6))
	}

	// After all that, double-check that writes to an out-of-capacity Pchan will not block.
	s := d.getSaver(ctx, f1)
	close(s.Pchan)
	close(s.UUIDchan)
	s.Pchan = make(chan gopacket.Packet) // This will never be read.
	d.savePacket(ctx, f1packets[0])
	// If this doesn't block, then success!
}

func TestUUIDWontBlock(t *testing.T) {
	// The flow in question...
	f := FullFlow{
		lo:  "ip1",
		hi:  "ip2",
		loP: 1,
		hiP: 2,
	}
	var e UUIDEvent
	e.Flow = f
	e.UUID = "testUUID"
	e.Timestamp = time.Now()

	dir, err := ioutil.TempDir("", "TestUUIDWontBlock")
	rtx.Must(err, "Could not create directory")
	defer os.RemoveAll(dir)

	d := New(anonymize.New(anonymize.None), dir, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		pChan := make(chan gopacket.Packet)
		gcTimer := make(chan time.Time)
		d.CapturePackets(ctx, pChan, gcTimer)
		// Does not run forever or crash == success
		wg.Done()
	}()

	// Write to the UUID channel 1000 times (more than exhausting its buffer)
	for i := 0; i < 1000; i++ {
		log.Println(i)
		d.UUIDChan <- e
	}
	// Lose all channel-read race conditions.
	time.Sleep(100 * time.Millisecond)
	// Ensure that reads of that channel never block. If the cancel() has an
	// effect, then it must be true that the reads did not block.
	cancel()
	wg.Wait()
	// No freeze == success!
}
