package demuxer

import (
	"context"
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/packet-headers/saver"
)

type fakePacketSource struct {
	packets []gopacket.Packet
	c       chan gopacket.Packet
}

func (f *fakePacketSource) run() {
	if f.packets != nil {
		for _, p := range f.packets {
			f.c <- p
		}
	}
}

func (f *fakePacketSource) Packets() chan gopacket.Packet {
	return f.c
}

func TestDemuxerDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestDemuxerDryRun")
	rtx.Must(err, "Could not create directory")

	d := New(anonymize.New(anonymize.None), dir, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	f := &fakePacketSource{c: make(chan gopacket.Packet)}
	go func() {
		f.run()
		close(f.c)
	}()
	d.CapturePackets(ctx, f)
	// Does not run forever or crash == success
}

func TestDemuxerWithRealPcaps(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestDemuxerWithv4Pcap")
	rtx.Must(err, "Could not create directory")

	d := New(anonymize.New(anonymize.None), dir, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	f := &fakePacketSource{c: make(chan gopacket.Packet)}

	// Get packets from a wireshark-produced pcap file.
	handle, err := pcap.OpenOffline("../testdata/v4.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var f1, f2 FullFlow
	for p := range ps.Packets() {
		f1 = FullFlow{p.NetworkLayer().NetworkFlow(), p.TransportLayer().TransportFlow()}
		f.packets = append(f.packets, p)
	}
	handle, err = pcap.OpenOffline("../testdata/v6.pcap")
	rtx.Must(err, "Could not open golden pcap file")
	ps = gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range ps.Packets() {
		f2 = FullFlow{p.NetworkLayer().NetworkFlow(), p.TransportLayer().TransportFlow()}
		f.packets = append(f.packets, p)
	}

	go func() {
		// We close f1 to simulate a full channel.
		t1 := d.GetSaver(ctx, f1)
		t1.UUIDchan <- saver.UUIDEvent{
			UUID:      "flow1",
			Timestamp: time.Date(2013, time.October, 31, 1, 2, 3, 4, time.UTC),
		}
		close(t1.Pchan)
		t1.Pchan = make(chan gopacket.Packet) // Zero capacity for this flow's channel and nothing will ever read it.
		// We leave f2 ready to go.
		f.run()
		d.Close(f1)
		d.GetSaver(ctx, f2).UUIDchan <- saver.UUIDEvent{
			UUID:      "flow2",
			Timestamp: time.Date(2013, time.October, 30, 1, 2, 3, 4, time.UTC),
		}
		d.Close(f2)
		close(f.c)
	}()

	d.CapturePackets(ctx, f)

	// Verify that files were created.

	// Verify their contents.
}
