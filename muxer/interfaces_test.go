package muxer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/rtx"
)

func channelFromFile(fname string) <-chan gopacket.Packet {
	// Get packets from a wireshark-produced pcap file.
	handle, err := pcap.OpenOffline(fname)
	rtx.Must(err, "Could not open golden pcap file %s", fname)
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	return ps.Packets()
}

func TestMuxPacketsUntilSourceExhaustion(t *testing.T) {
	// Open our two testfiles
	ins := []<-chan gopacket.Packet{
		channelFromFile("../testdata/v4.pcap"),
		channelFromFile("../testdata/v6.pcap"),
	}
	out := make(chan gopacket.Packet)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		// Mux the packets from each.
		muxPackets(context.Background(), ins, out)
		wg.Done()
	}()
	// The only way that this will close is if we exhaust all the input channels
	// and they each close. So let's do that.
	pcount := 0
	for range out {
		pcount++
	}
	wg.Wait()
	// Verify that the combined flow contains the right number of packets.
	if pcount != 20 {
		t.Errorf("pcount should be 20, not %d", pcount)
	}
}

func TestMuxPacketsUntilContextCancellation(t *testing.T) {
	ins := []<-chan gopacket.Packet{
		make(chan gopacket.Packet),
		make(chan gopacket.Packet),
	}
	out := make(chan gopacket.Packet)
	wg := sync.WaitGroup{}
	wg.Add(1)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Mux the packets from each.
		muxPackets(ctx, ins, out)
		wg.Done()
	}()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	// The input channels will never close, so only context cancellation will work.
	pcount := 0
	for range out {
		pcount++
	}
	wg.Wait()
	// If we got to here, then muxPackets terminated!  Hooray!

	// Verify that the combined flow contained no packets.
	if pcount != 0 {
		t.Errorf("pcount should be 0, not %d", pcount)
	}

}

func TestMustMakeFilter(t *testing.T) {
	f := mustMakeFilter([]string{"lo"})
	if f != "tcp" {
		t.Error("loopback resulted in non-empty filter")
	}
	f = mustMakeFilter([]string{})
	if f != "tcp" {
		t.Error("empty interface list resulted in non-empty filter")
	}
	ifaces, err := net.Interfaces()
	ifNames := []string{}
	for _, iface := range ifaces {
		ifNames = append(ifNames, iface.Name)
	}

	rtx.Must(err, "Could not get interface list")
	f = mustMakeFilter(ifNames)
	if f == "" {
		t.Error("Non-empty interface list resulted in empty filter")
	}
	// Verify that the filter is a well-formed BPF filter.
	_, err = pcap.NewBPF(layers.LinkTypeEthernet, 256, f)
	rtx.Must(err, "Could not parse bpf %q", f)
}

func fakePcapOpenLive(filename string, _ int32, _ bool, _ time.Duration) (*pcap.Handle, error) {
	return pcap.OpenOffline(filename)
}

func fakeInterfaceByName(name string) (*net.Interface, error) {
	return nil, nil
}

func TestMustCaptureOnInterfaces(t *testing.T) {
	netInterfaceByName = fakeInterfaceByName
	defer func() { netInterfaceByName = net.InterfaceByName }()

	wg := sync.WaitGroup{}
	packets := make(chan gopacket.Packet)
	wg.Add(1)
	go func() {
		MustCaptureTCPOnInterfaces(
			context.Background(),
			[]string{"../testdata/v4.pcap", "../testdata/v6.pcap"},
			packets,
			fakePcapOpenLive,
			0,
		)
		wg.Done()
	}()

	count := 0
	for range packets {
		count++
	}
	wg.Wait()
	if count != 20 {
		t.Errorf("Was supposed to see 20 packets, but instead saw %d", count)
	}
}
