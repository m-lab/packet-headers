package demuxer

import (
	"net"
	"testing"
)

func TestFullFlowFrom4Tuple(t *testing.T) {
	tests := []struct {
		name    string
		srcIP   net.IP
		srcPort uint16
		dstIP   net.IP
		dstPort uint16
	}{
		{
			name:    "Different hosts",
			srcIP:   net.ParseIP("10.1.1.1").To4(),
			srcPort: 2000,
			dstIP:   net.ParseIP("192.168.0.1").To4(),
			dstPort: 1000,
		},
		{
			name:    "Same host, different ports",
			srcIP:   net.ParseIP("10.2.3.4").To4(),
			srcPort: 2000,
			dstIP:   net.ParseIP("10.2.3.4").To4(),
			dstPort: 1000,
		},
		{
			name:    "Different v6 hosts",
			srcIP:   net.ParseIP("2:3::").To16(),
			srcPort: 2000,
			dstIP:   net.ParseIP("4:5::").To16(),
			dstPort: 1000,
		},
		{
			name:    "Same v6 host, different ports",
			srcIP:   net.ParseIP("1::").To16(),
			srcPort: 2000,
			dstIP:   net.ParseIP("1::").To16(),
			dstPort: 1000,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f1 := FullFlowFrom4Tuple(tt.srcIP, tt.srcPort, tt.dstIP, tt.dstPort)
			f2 := FullFlowFrom4Tuple(tt.dstIP, tt.dstPort, tt.srcIP, tt.srcPort)
			if f1 != f2 {
				t.Errorf("%+v != %+v", f1, f2)
			}
		})
	}
}
