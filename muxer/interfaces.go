// Package muxer helps solve the problem that captures take place only on a
// per-interface basis, but tcp-info collects flow information with no reference
// to the underlying interface.
package muxer

import (
	"context"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/rtx"
)

func forwardPackets(ctx context.Context, in <-chan gopacket.Packet, out chan<- gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case p, ok := <-in:
			if !ok {
				return
			}
			out <- p
		case <-ctx.Done():
			return
		}
	}
}

// muxPackets causes each packet on every input channel to be sent to the output channel.
func muxPackets(ctx context.Context, in []<-chan gopacket.Packet, out chan<- gopacket.Packet) {
	wg := sync.WaitGroup{}
	for _, inC := range in {
		wg.Add(1)
		go forwardPackets(ctx, inC, out, &wg)
	}

	wg.Wait()
	close(out)
}

// PcapHandleOpener is a type to allow injection of fake packet captures to aid
// in testing. It is exactly the type of pcap.OpenLive, and in production code
// every variable of this type should be set to pcap.OpenLive.
type PcapHandleOpener func(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *pcap.Handle, _ error)

// MustCaptureTCPOnInterfaces fires off a packet capture on every one of the
// passed-in list of interfaces, and then muxes the resulting packet streams to
// all be sent to the passed-in packets channel.
func MustCaptureTCPOnInterfaces(ctx context.Context, interfaces []string, packets chan<- gopacket.Packet, opener PcapHandleOpener, maxHeaderSize int32) {
	// Capture packets on every interface.
	packetCaptures := make([]<-chan gopacket.Packet, 0)
	for _, iface := range interfaces {
		// Open a packet capture
		handle, err := opener(iface, maxHeaderSize, true, pcap.BlockForever)
		rtx.Must(err, "Could not create libpcap client for %q", iface)
		rtx.Must(handle.SetBPFFilter("tcp"), "Could not set up BPF filter for TCP")

		// Stop packet capture when this function exits.
		defer handle.Close()

		// Save the packet capture channel.
		packetCaptures = append(packetCaptures, gopacket.NewPacketSource(handle, layers.LinkTypeEthernet).Packets())
	}

	// multiplex packets until all packet sources are exhausted or the context
	// is cancelled.
	muxPackets(ctx, packetCaptures, packets)
}
