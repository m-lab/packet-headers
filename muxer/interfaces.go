// Package muxer helps solve the problem that captures take place only on a
// per-interface basis, but tcp-info collects flow information with no reference
// to the underlying interface.
package muxer

import (
	"context"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/packet-headers/metrics"
)

// PcapHandleOpener is a type to allow injection of fake packet captures to aid
// in testing. It is exactly the type of pcap.OpenLive, and in production code
// every variable of this type should be set to pcap.OpenLive.
type PcapHandleOpener func(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *pcap.Handle, _ error)

// Injected functions to support whitebox testing.
var (
	netInterfaceByName = net.InterfaceByName
)

func forwardPackets(ctx context.Context, in <-chan gopacket.Packet, out chan<- gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()
	metrics.InterfacesBeingCaptured.Inc()
	defer metrics.InterfacesBeingCaptured.Dec()

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

func mustMakeFilter(interfaces []string) string {
	filters := []string{}
	for _, ifName := range interfaces {
		iface, err := netInterfaceByName(ifName)
		rtx.Must(err, "Could not get named interface %s", ifName)
		if iface == nil || iface.Flags&net.FlagLoopback != 0 {
			// Skip nil interfaces and loopback addresses
			continue
		}
		addrs, err := iface.Addrs()
		rtx.Must(err, "Could not get addresses for interface %s", ifName)
		for _, addr := range addrs {
			a := addr.String()
			if strings.Contains(a, "/") {
				a = strings.Split(a, "/")[0]
			}
			if strings.Contains(a, ":") {
				filters = append(filters, "ip6 host "+a)
			} else {
				filters = append(filters, "ip host "+a)
			}
		}
	}
	if len(filters) == 0 {
		return "tcp"
	}
	return "tcp and ( " + strings.Join(filters, " or ") + ")"
}

// MustCaptureTCPOnInterfaces fires off a packet capture on every one of the
// passed-in list of interfaces, and then muxes the resulting packet streams to
// all be sent to the passed-in packets channel.
func MustCaptureTCPOnInterfaces(ctx context.Context, interfaces []string, packets chan<- gopacket.Packet, pcapOpenLive PcapHandleOpener, maxHeaderSize int32) {
	// Capture packets on every interface.
	packetCaptures := make([]<-chan gopacket.Packet, 0)
	// Only capture packets destined for a non-localhost local IP.
	filter := mustMakeFilter(interfaces)
	log.Printf("Using BPF filter %q\n", filter)
	for _, iface := range interfaces {
		// Open a packet capture
		handle, err := pcapOpenLive(iface, maxHeaderSize, true, pcap.BlockForever)
		rtx.Must(err, "Could not create libpcap client for %q", iface)
		rtx.Must(handle.SetBPFFilter(filter), "Could not set up BPF filter for TCP")

		// Stop packet capture when this function exits.
		defer handle.Close()

		// Save the packet capture channel.
		packetCaptures = append(packetCaptures, gopacket.NewPacketSource(handle, layers.LinkTypeEthernet).Packets())
	}

	// multiplex packets until all packet sources are exhausted or the context
	// is cancelled.
	muxPackets(ctx, packetCaptures, packets)
}
