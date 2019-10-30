package demuxer

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// FullFlow characterizes a TCP/IP flow without judgement about what direction
// the flow is. The lexicographically lowest IP/Port combination should always
// be first. It is not meant to be human-readable, and is instead only designed
// to be used as a key in a map.
type FullFlow struct {
	lo, hi   string
	loP, hiP uint16
}

// fromPacket converts a packet's TCP 4-tuple into a FullFlow suitable for being
// a map key. Never pass fromPacket a non-TCP/IP packet - it will crash.
func fromPacket(p gopacket.Packet) FullFlow {
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
	return FullFlowFrom4Tuple(ip1, ip1P, ip2, ip2P)
}

// FullFlowFrom4Tuple creates a FullFlow (suitable for use as a map key) from a TCP 4-tuple.
func FullFlowFrom4Tuple(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) FullFlow {
	srcIPS := string(srcIP)
	dstIPS := string(dstIP)
	if srcIPS < dstIPS || (srcIPS == dstIPS && srcPort < dstPort) {
		return FullFlow{srcIPS, dstIPS, srcPort, dstPort}
	}
	return FullFlow{dstIPS, srcIPS, dstPort, srcPort}
}
