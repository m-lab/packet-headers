package demuxer

import (
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FlowKey characterizes a TCP/IP flow without judgement about what direction
// the flow is. The lexicographically lowest IP/Port combination should always
// be first. It is not meant to be human-readable, and is instead only designed
// to be used as a key in a map.
type FlowKey struct {
	lo, hi   string
	loP, hiP uint16
}

func (f *FlowKey) String() string {
	return fmt.Sprintf("%s:%d<->%s:%d", net.IP([]byte(f.lo)).String(), f.loP, net.IP([]byte(f.hi)).String(), f.hiP)
}

// fromPacket converts a packet's TCP 4-tuple into a FlowKey suitable for being
// a map key. Never pass fromPacket a non-TCP/IP packet - it will crash.
func fromPacket(p gopacket.Packet) FlowKey {
	nl := p.NetworkLayer()
	var ip1, ip2 net.IP
	switch nl.LayerType() {
	case layers.LayerTypeIPv4:
		ip1 = nl.(*layers.IPv4).SrcIP
		ip2 = nl.(*layers.IPv4).DstIP
	case layers.LayerTypeIPv6:
		ip1 = nl.(*layers.IPv6).SrcIP
		ip2 = nl.(*layers.IPv6).DstIP
	}
	f := p.TransportLayer().(*layers.TCP)
	ip1P := uint16(f.SrcPort)
	ip2P := uint16(f.DstPort)
	return FlowKeyFrom4Tuple(ip1, ip1P, ip2, ip2P)
}

// FlowKeyFrom4Tuple creates a FlowKey (suitable for use as a map key) from a
// TCP 4-tuple. This function is called once per packet, by the demuxer, and
// once per flow, by the tcpeventsocket handler. Because it is called once per
// packet, it should be as efficient as possible.
//
// IPv4 addresses passed in must be 4 bytes, because we do byte-based
// comparisons with sub-slices of packets retrieved from the wire.
func FlowKeyFrom4Tuple(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) FlowKey {
	srcIPS := string(srcIP)
	dstIPS := string(dstIP)
	if srcIPS < dstIPS || (srcIPS == dstIPS && srcPort < dstPort) {
		return FlowKey{srcIPS, dstIPS, srcPort, dstPort}
	}
	return FlowKey{dstIPS, srcIPS, dstPort, srcPort}
}
