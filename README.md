# packet-headers

The packet-headers service provides a binary which collects PCAP headers for all
incoming TCP flows and saves each stream of packet captures into a per-stream
file where the filename is the [UUID](https://github.com/m-lab/uuid) of the TCP
flow.  It should only save the packet headers, and it should zero out enough parts of the client IP address in each header to ensure client anonymity.

## Design

(This should eventually be broken out into its own file DESIGN.md)

Use the [gopacket](https://github.com/google/gopacket/pcap) libraries to sniff
all packets on the wire.  For v1, where we are only interested in TCP flows,
install a [Berkeley Packet
Filter](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) to ensure that
only TCP packets get sent to the packet-headers daemon.

### Modifications to tcp-info

To fulfil its obligations (a per-flow file containing the UUID) packet-headers
will need an addition to the tcp-info service.  In this addition, packet-headers
will connect as a client to a well-specified port on localhost or a unix-domain socket
that is served by tcp-info.  Whenever a new stream begins or ends, the tcp-info system will post the
5-tuple of the stream and its UUID on the open connection.  In this way, the
packet-headers system will learn about new connections from the kernel, which is
the only true authority about what is and isn't a new connection.  It will also
learn when the connection is closed, which is the one true signal for when to
safely close the pcap file.

## Appendix

### FAQ: What about UDP? ICMP?

A good idea, but not required for v1.
