package muxer

import (
	"testing"
)

func TestMuxPackets(t *testing.T) {
	// Open our two testfiles
	// Mux the packets from each.
	// Close each channel.
	// Verify that all input channels closing causes the output channel to close.
	// Verify that the combined flow contains the right number of packets.
}
