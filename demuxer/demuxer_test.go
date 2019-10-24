package demuxer

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/gopacket"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
)

type fakePacketSource struct {
	packets []gopacket.Packet
}

func (f *fakePacketSource) Packets() chan gopacket.Packet {
	ch := make(chan gopacket.Packet)
	go func() {
		if f.packets != nil {
			for _, p := range f.packets {
				ch <- p
			}
		}
		close(ch)
	}()
	return ch
}

func TestDemuxerLoopTerminatesWithPacketSource(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestDemuxerMainLoop")
	rtx.Must(err, "Could not create directory")

	d := New(anonymize.New(anonymize.None), dir, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	f := &fakePacketSource{}
	d.CapturePackets(ctx, f)
	// Does not run forever or crash == success
}
