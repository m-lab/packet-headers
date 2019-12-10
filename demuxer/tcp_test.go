package demuxer

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/packet-headers/saver"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

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

func TestTCPDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestTCPDryRun")
	rtx.Must(err, "Could not create directory")
	defer os.RemoveAll(dir)

	tcpdm := NewTCP(anonymize.New(anonymize.None), dir, 500*time.Millisecond, time.Second, true)

	// While we have a demuxer created, make sure that the processing path for
	// packets does not crash when given a nil packet.
	tcpdm.savePacket(context.Background(), nil) // No crash == success

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	cancel()

	pChan := make(chan gopacket.Packet)
	gcTimer := make(chan time.Time)
	tcpdm.CapturePackets(ctx, pChan, gcTimer)
	close(gcTimer)
	close(pChan)
	// Does not run forever or crash == success
}

type statusTracker struct {
	stillPresent, discarded int
	mu                      sync.Mutex
}

func (s *statusTracker) GC(stillPresent, discarded int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stillPresent = stillPresent
	s.discarded = discarded
}

func (s *statusTracker) Get() statusTracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return statusTracker{
		stillPresent: s.stillPresent,
		discarded:    s.discarded,
	}
}

func TestTCPWithRealPcaps(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestTCPWithRealPcaps")
	rtx.Must(err, "Could not create directory")
	defer os.RemoveAll(dir)

	tcpdm := NewTCP(anonymize.New(anonymize.None), dir, 500*time.Millisecond, time.Second, true)
	st := &statusTracker{}
	tcpdm.status = st
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pChan := make(chan gopacket.Packet)

	wg := sync.WaitGroup{}
	wg.Add(1)
	gc := make(chan time.Time)
	// Run the demuxer and send it events.
	go func() {
		tcpdm.CapturePackets(ctx, pChan, gc)
		wg.Done()
	}()

	// Get packets from a wireshark-produced pcap file.
	handle, err := pcap.OpenOffline("../testdata/v4.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var flow1, flow2 FlowKey
	flow1packets := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		flow1 = fromPacket(p)
		flow1packets = append(flow1packets, p)
	}

	handle, err = pcap.OpenOffline("../testdata/v6.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	flow2packets := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		flow2 = fromPacket(p)
		flow2packets = append(flow2packets, p)
	}

	// Now that we have the packets, we want to test:
	// 1. packets arriving before the UUID
	// 2. UUID arriving before packets
	// 3. packets arriving after one round of GC
	// 4. packets for two different flows arriving intermingled
	// 5. that GC will close old flows but not new flows
	//
	// So we:
	// (a) send the uuid for flow 1,
	// (b) send some packets for flow 1,
	// (c) send all packets for flow 2,
	// (d) send the uuid for flow 2,
	// (e) call GC,
	// (f) send the rest of the packets for flow 1.
	// (g) call GC again
	//
	// 1 is tested by (c,d)
	// 2 is tested by (a,b)
	// 3 is tested by (e,f)
	// 4 is tested by (b,d,f)
	// 5 is tested by (a,b,c,d,e,f,g)

	tcpdm.UUIDChan <- UUIDEvent{
		UUIDEvent: saver.UUIDEvent{
			UUID:      "flow1",
			Timestamp: time.Date(2013, time.October, 31, 1, 2, 3, 4, time.UTC),
		},
		Flow: flow1,
	}
	pChan <- flow1packets[0]
	pChan <- flow1packets[1]

	for _, p := range flow2packets {
		pChan <- p
	}

	tcpdm.UUIDChan <- UUIDEvent{
		UUIDEvent: saver.UUIDEvent{
			UUID:      "flow2",
			Timestamp: time.Date(2013, time.October, 30, 1, 2, 3, 4, time.UTC),
		},
		Flow: flow2,
	}

	// Lose all race conditions, then fire the GC to
	// cause the flows to become oldFlows.
	time.Sleep(100 * time.Millisecond)
	gc <- time.Now()
	// Send a the rest of the flow1 packets to ensure flow 1 is not garbage collected.
	for _, p := range flow1packets[2:] {
		pChan <- p
	}
	// Lose all race conditions, then fire the GC to cause one flow to become an
	// oldFlow and the other to be garbage collected.
	time.Sleep(100 * time.Millisecond)
	gc <- time.Now()
	// Lose all race conditions again.
	time.Sleep(100 * time.Millisecond)
	// Verify that one flow was garbage collected.
	s := st.Get()
	if s.stillPresent != 1 || s.discarded != 1 {
		t.Errorf("Should have 1 flow left and 1 flow collected, not %d and %d", s.stillPresent, s.discarded)
	}
	gc <- time.Now()
	time.Sleep(100 * time.Millisecond)
	cancel()
	wg.Wait()

	// Busy-wait until both files appear on disk.
	var err1, err2 error
	err1 = errors.New("start out with an error")
	for err1 != nil || err2 != nil {
		_, err1 = os.Stat(dir + "/2013/10/31/flow1.pcap.gz")
		_, err2 = os.Stat(dir + "/2013/10/30/flow2.pcap.gz")
		time.Sleep(100 * time.Millisecond)
	}

	// Verify the files' contents.
	rtx.Must(exec.Command("gunzip", dir+"/2013/10/31/flow1.pcap.gz").Run(), "Could not unzip flow1")
	handle, err = pcap.OpenOffline(dir + "/2013/10/31/flow1.pcap")
	rtx.Must(err, "Could not open golden pcap file: flow1.pcap")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	v4 := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		v4 = append(v4, p)
	}
	if len(v4) != 12 {
		t.Errorf("%+v should have length 12 not %d", v4, len(v4))
	}

	rtx.Must(exec.Command("gunzip", dir+"/2013/10/30/flow2.pcap.gz").Run(), "Could not unzip flow2")
	handle, err = pcap.OpenOffline(dir + "/2013/10/30/flow2.pcap")
	rtx.Must(err, "Could not open golden pcap file: flow2.pcap")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	v6 := make([]gopacket.Packet, 0)
	for p := range ps.Packets() {
		v6 = append(v6, p)
	}
	if len(v6) != 8 {
		t.Errorf("%+v should have length 8 not %d", v6, len(v6))
	}

	// After all that, also check that writes to an out-of-capacity Pchan will
	// not block.
	sav := tcpdm.getSaver(ctx, flow1)
	close(sav.Pchan)
	close(sav.UUIDchan)
	// This new channel assigned to sav.Pchan will never be read, so if a blocking
	// write is performed then this goroutine will block.
	sav.Pchan = make(chan gopacket.Packet)
	tcpdm.savePacket(ctx, flow1packets[0])
	// If this doesn't block, then success!
}

func TestUUIDWontBlock(t *testing.T) {
	// The flow in question...
	f := FlowKey{
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

	tcpdm := NewTCP(anonymize.New(anonymize.None), dir, 15*time.Second, 30*time.Second, true)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)

	var wg sync.WaitGroup
	wg.Add(1)
	gcTimer := make(chan time.Time)
	go func() {
		pChan := make(chan gopacket.Packet)
		tcpdm.CapturePackets(ctx, pChan, gcTimer)
		// Does not run forever or crash == success
		wg.Done()
	}()

	// Write to the UUID channel 1000 times (more than exhausting its buffer)
	for i := 0; i < 1000; i++ {
		tcpdm.UUIDChan <- e
	}
	gcTimer <- time.Now()
	// Lose all channel-read race conditions.
	time.Sleep(100 * time.Millisecond)
	// Ensure that reads of that channel never block. If the cancel() has an
	// effect, then it must be true that the reads did not block.
	cancel()
	wg.Wait()
	// No freeze == success!
}
