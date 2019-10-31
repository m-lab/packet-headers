package demuxer

import (
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

// FlowKeyFrom4Tuple creates a FlowKey (suitable for use as a map key) from a TCP 4-tuple.
func FlowKeyFrom4Tuple(srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16) FlowKey {
	srcIPS := string(srcIP)
	dstIPS := string(dstIP)
	if srcIPS < dstIPS || (srcIPS == dstIPS && srcPort < dstPort) {
		return FlowKey{srcIPS, dstIPS, srcPort, dstPort}
	}
	return FlowKey{dstIPS, srcIPS, dstPort, srcPort}
}