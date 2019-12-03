package demuxer

import (
	"net"
	"testing"

	"github.com/m-lab/go/anonymize"
)

func TestFlowKeyFrom4Tuple(t *testing.T) {
	tests := []struct {
		name        string
		srcIP       net.IP
		srcPort     uint16
		dstIP       net.IP
		dstPort     uint16
		str         string
		netblockStr string
	}{
		{
			name:        "Different hosts",
			srcIP:       net.ParseIP("10.1.1.1").To4(),
			srcPort:     2000,
			dstIP:       net.ParseIP("192.168.0.1").To4(),
			dstPort:     1000,
			str:         "10.1.1.1:2000<->192.168.0.1:1000",
			netblockStr: "10.1.1.0:2000<->192.168.0.0:1000",
		},
		{
			name:        "Same host, different ports",
			srcIP:       net.ParseIP("10.2.3.4").To4(),
			srcPort:     2000,
			dstIP:       net.ParseIP("10.2.3.4").To4(),
			dstPort:     1000,
			str:         "10.2.3.4:1000<->10.2.3.4:2000",
			netblockStr: "10.2.3.0:1000<->10.2.3.0:2000",
		},
		{
			name:        "Different v6 hosts",
			srcIP:       net.ParseIP("2abc:3:4:5:6:7:8:1").To16(),
			srcPort:     2000,
			dstIP:       net.ParseIP("4abc:5:6:7:8:1:2:3").To16(),
			dstPort:     1000,
			str:         "2abc:3:4:5:6:7:8:1:2000<->4abc:5:6:7:8:1:2:3:1000",
			netblockStr: "2abc:3:4:5:::2000<->4abc:5:6:7:::1000",
		},
		{
			name:        "Same v6 host, different ports",
			srcIP:       net.ParseIP("1::").To16(),
			srcPort:     2000,
			dstIP:       net.ParseIP("1::").To16(),
			dstPort:     1000,
			str:         "1:::1000<->1:::2000",
			netblockStr: "1:::1000<->1:::2000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f1 := FlowKeyFrom4Tuple(tt.srcIP, tt.srcPort, tt.dstIP, tt.dstPort)
			f2 := FlowKeyFrom4Tuple(tt.dstIP, tt.dstPort, tt.srcIP, tt.srcPort)
			if f1 != f2 {
				t.Errorf("%+v != %+v", f1, f2)
			}
			nb := anonymize.New(anonymize.Netblock)
			if f1.Format(nb) != tt.netblockStr || f2.Format(nb) != tt.netblockStr {
				t.Errorf("Anonymized should be equal: %q, %q, %q", f1.Format(nb), f2.Format(nb), tt.netblockStr)
			}
			// Applying netblock anonymization before applying no anonymization
			// also tests that the anonymization of the log messages does not
			// cause the actual data inside the struct to become anonymized
			// (which would be bad, and mess up the demuxer).
			none := anonymize.New(anonymize.None)
			if f1.Format(none) != tt.str || f2.Format(none) != tt.str {
				t.Errorf("Strings should be equal: %q, %q, %q", f1.Format(none), f2.Format(none), tt.str)
			}
		})
	}
}
