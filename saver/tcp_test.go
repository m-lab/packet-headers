package saver

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
)

func TestMinInt(t *testing.T) {
	for _, c := range []struct{ x, y, want int }{
		{1, 0, 0},
		{1, 1, 1},
		{0, 1, 0},
		{0, 0, 0},
	} {
		if minInt(c.x, c.y) != c.want {
			t.Errorf("Bad minInt (%+v)", c)
		}
	}
}

func TestAnonymizationWontCrashOnNil(t *testing.T) {
	a := anonymize.New(anonymize.Netblock)

	// Try to anonymize packets with no IP data.
	anonymizePacket(a, nil) // No crash == success
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{} // See SerializeOptions for more details.
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			SrcMAC: net.HardwareAddr("123456"),
			DstMAC: net.HardwareAddr("654321"),
		},
	)
	ethOnlyPacket := gopacket.NewPacket(
		buf.Bytes(),
		layers.LayerTypeEthernet,
		gopacket.Default)
	anonymizePacket(a, ethOnlyPacket) // No crash == success

	// All other cases are tested by the TestSaverWithRealv4Data and
	// TestSaverWithRealv6Data cases later.
}

type statusTracker struct {
	status string
	past   []string
}

func (s *statusTracker) Set(state string) {
	if s.status == state {
		return
	}
	s.past = append(s.past, s.status)
	s.status = state
}

func (s *statusTracker) Done() {
	s.Set("stopped")
}

func (s *statusTracker) Get() string {
	return s.status
}

func TestSaverDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverDryRun")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	s := newTCP(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)

	// Send a UUID but never send any packets.
	s.UUIDchan <- UUIDEvent{"testUUID", tstamp}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Wait until the status is readingpackets or the surrounding context has been cancelled.
	go func() {
		for s.state.Get() != "readingpackets" && ctx.Err() == nil {
			time.Sleep(1 * time.Millisecond)
		}
		cancel()
	}()

	s.start(ctx, 10*time.Second) // Give the disk IO 10 seconds to happen.
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "dircreation", "readingpackets", "nopacketserror"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverNoUUID(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverNoUUID")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	s := newTCP(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	s.start(ctx, 10*time.Second)
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "uuiderror"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverNoUUIDClosedUUIDChan(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverNoUUID")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	s := newTCP(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	close(s.UUIDchan)
	s.start(context.Background(), 10*time.Second)
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "uuidchanerror"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverCantMkdir(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverCantMkdir")
	rtx.Must(err, "Could not create tempdir")
	rtx.Must(os.Chmod(dir, 0111), "Could not chmod dir to unwriteable")
	defer os.RemoveAll(dir)

	s := newTCP(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	s.UUIDchan <- UUIDEvent{"testUUID", time.Now()}
	s.start(context.Background(), 10*time.Second)

	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "dircreation", "mkdirerror"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverCantCreate(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverCantCreate")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	s := newTCP(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	// Get the packet data ready to send.
	h, err := pcap.OpenOffline("../testdata/v4.pcap")
	rtx.Must(err, "Could not open v4.pcap")
	ps := gopacket.NewPacketSource(h, h.LinkType())

	// A UUID containing a non-shell-safe character will never happen in
	// practice, but it does cause the resulting file to fail in os.Create()
	s.UUIDchan <- UUIDEvent{"test/UUID", time.Now()}
	for p := range ps.Packets() {
		s.Pchan <- p
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	s.start(ctx, 100*time.Millisecond)

	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "dircreation", "readingpackets", "savingfile", "filewriteerror", "discardingpackets"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverWithRealv4Data(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverWithRealv4Data")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Send a UUID and then some packets.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := StartNew(ctx, anonymize.New(anonymize.Netblock), dir, 10*time.Second)

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)
	s.UUIDchan <- UUIDEvent{"testUUID", tstamp}

	go func() {
		// Get packets from a wireshark-produced pcap file.
		handle, err := pcap.OpenOffline("../testdata/v4.pcap")
		rtx.Must(err, "Could not open golden pcap file")
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		// Send packets down the packet channel
		for p := range ps.Packets() {
			s.Pchan <- p
		}
		// Stop the saver.
		close(s.Pchan)
	}()

	for s.State() != "stopped" {
		time.Sleep(time.Millisecond)
	}

	log.Println("reading data from", dir+"/2000/01/02/testUUID.pcap")
	handle, err := pcap.OpenOffline(dir + "/2000/01/02/testUUID.pcap")
	rtx.Must(err, "Could not open written pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	for p := range ps.Packets() {
		packets = append(packets, p)
	}

	if len(packets) != 12 {
		t.Error("Bad length (should be 12):", len(packets))
	}
	for _, p := range packets {
		al := p.ApplicationLayer()
		if al != nil {
			data := al.LayerContents()
			for _, b := range data {
				if b != 0 {
					t.Error("All application layer data is supposed to be zeroed, but was not in", p)
					break
				}
			}
		}
		// We have packets going both directions, so the srcIP and dstIP will
		// swap roles over the course of the packet capture, as will the src and
		// dst ports.
		srcIP := p.NetworkLayer().(*layers.IPv4).SrcIP.To4()
		if !reflect.DeepEqual(srcIP, net.ParseIP("172.17.0.0").To4()) && !reflect.DeepEqual(srcIP, net.ParseIP("91.189.88.0").To4()) {
			t.Error("IPv4 src addr was not anonymized:", srcIP)
		}
		dstIP := p.NetworkLayer().(*layers.IPv4).DstIP.To4()
		if !reflect.DeepEqual(dstIP, net.ParseIP("172.17.0.0").To4()) && !reflect.DeepEqual(dstIP, net.ParseIP("91.189.88.0").To4()) {
			t.Error("IPv4 dst addr was not anonymized:", dstIP)
		}
		port1, port2 := p.TransportLayer().TransportFlow().Endpoints()
		if port1.String() != "49834" && port1.String() != "80" {
			t.Error("Bad port1 snuck in")
		}
		if port2.String() != "49834" && port2.String() != "80" {
			t.Error("Bad port2 snuck in")
		}
	}
}

func TestSaverWithRealv6Data(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverWithRealv6Data")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	// Send a UUID and then some packets.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := StartNew(ctx, anonymize.New(anonymize.Netblock), dir, 10*time.Second)

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)
	s.UUIDchan <- UUIDEvent{"testUUID", tstamp}

	go func() {
		// Get packets from a wireshark-produced pcap file.
		handle, err := pcap.OpenOffline("../testdata/v6.pcap")
		rtx.Must(err, "Could not open golden pcap file")
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		// Send packets down the packet channel
		for p := range ps.Packets() {
			s.Pchan <- p
		}
		// Stop the saver.
		close(s.Pchan)
	}()

	for s.State() != "stopped" {
		time.Sleep(time.Millisecond)
	}

	log.Println("reading data from", dir+"/2000/01/02/testUUID.pcap")
	handle, err := pcap.OpenOffline(dir + "/2000/01/02/testUUID.pcap")
	rtx.Must(err, "Could not open written pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	for p := range ps.Packets() {
		packets = append(packets, p)
	}

	if len(packets) != 8 {
		t.Error("Bad length (should be 8):", len(packets))
	}
	for _, p := range packets {
		al := p.ApplicationLayer()
		if al != nil {
			data := al.LayerContents()
			for _, b := range data {
				if b != 0 {
					t.Error("All application layer data is supposed to be zeroed, but was not in", p)
					break
				}
			}
		}
		srcIP := p.NetworkLayer().(*layers.IPv6).SrcIP
		if srcIP[0] == 0 {
			t.Error("First byte of v6 addr should not be zero")
		}
		for _, b := range srcIP[8:] {
			if b != 0 {
				t.Error("All high-end v6 address bytes should be zeroed out in", p)
			}
		}
		dstIP := p.NetworkLayer().(*layers.IPv6).DstIP
		if dstIP[0] == 0 {
			t.Error("First byte of v6 addr should not be zero")
		}
		for _, b := range dstIP[8:] {
			if b != 0 {
				t.Error("All high-end v6 address bytes should be zeroed out in", p)
			}
		}

		// If this doesn't crash, then the transport layer is not nil - success!
		p.TransportLayer().TransportFlow().Endpoints()
	}
}
