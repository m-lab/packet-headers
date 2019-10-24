package saver

import (
	"context"
	"encoding/hex"
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

func TestAnonymization(t *testing.T) {
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

	// Again, but now with actual IPv4 data in the packet.
	buf = gopacket.NewSerializeBuffer()
	ipv4 := &layers.IPv4{}
	// Hand-modified packet data from wireshark for 10.101.236.44 -> 10.211.118.21
	// IPs have been changed to prevent exposure of internal IPs.
	ipv4bytes, err := hex.DecodeString("4500006c489b4000400618770a65ec2c0ad37615")
	rtx.Must(err, "Could not decode byte string")
	rtx.Must(ipv4.DecodeFromBytes(ipv4bytes, gopacket.NilDecodeFeedback), "Could not reify v4 packet")
	gopacket.SerializeLayers(buf, opts, ipv4)
	ipv4Packet := gopacket.NewPacket(
		buf.Bytes(),
		layers.LayerTypeIPv4,
		gopacket.Default)
	if ipv4Packet.NetworkLayer().(*layers.IPv4).SrcIP.String() != "10.101.236.44" {
		t.Error("Failed to reify srcIP:", ipv4Packet.NetworkLayer().(*layers.IPv4).SrcIP.String())
	}
	if ipv4Packet.NetworkLayer().(*layers.IPv4).DstIP.String() != "10.211.118.21" {
		t.Error("Failed to reify dstIP:", ipv4Packet.NetworkLayer().(*layers.IPv4).DstIP.String())
	}
	// Perform the anonymization
	anonymizePacket(a, ipv4Packet)
	if ipv4Packet.NetworkLayer().(*layers.IPv4).SrcIP.String() != "10.101.236.0" {
		t.Error("Failed to anonymize srcIP:", ipv4Packet.NetworkLayer().(*layers.IPv4).SrcIP.String())
	}
	if ipv4Packet.NetworkLayer().(*layers.IPv4).DstIP.String() != "10.211.118.0" {
		t.Error("Failed to anonymize dstIP:", ipv4Packet.NetworkLayer().(*layers.IPv4).DstIP.String())
	}
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

func (s *statusTracker) Get() string {
	return s.status
}

func TestSaverDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverDryRun")
	rtx.Must(err, "Could not create tempdir")
	//defer os.RemoveAll(dir)

	s := newSaver(dir, anonymize.New(anonymize.None))
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
		s.Stop()
	}()

	s.start(ctx, 10*time.Second) // Give the disk IO 10 seconds to happen.
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "filecreation", "readingpackets", "nopacketserror"},
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

	s := newSaver(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	s.start(context.Background(), 10*time.Millisecond)
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

func TestSaverCantMkdir(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverCantMkdir")
	rtx.Must(err, "Could not create tempdir")
	rtx.Must(os.Chmod(dir, 0111), "Could not chmod dir to unwriteable")
	defer os.RemoveAll(dir)

	s := newSaver(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	s.UUIDchan <- UUIDEvent{"testUUID", time.Now()}
	s.start(context.Background(), 10*time.Second)

	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "filecreation", "mkdirerror"},
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

	s := newSaver(dir, anonymize.New(anonymize.None))
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	// A UUID containing a non-shell-safe character will never happen in
	// practice, but it does cause the resulting file to fail in os.Create()
	s.UUIDchan <- UUIDEvent{"test/UUID", time.Now()}
	s.start(context.Background(), 10*time.Second)

	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "filecreation", "createerror"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverWithRealData(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestSaverWithRealData")
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
		handle, err := pcap.OpenOffline("test.pcap")
		rtx.Must(err, "Could not open golden pcap file")
		ps := gopacket.NewPacketSource(handle, handle.LinkType())
		// Send packets down the packet channel
		for p := range ps.Packets() {
			s.Pchan <- p
		}
		// Stop the saver.
		s.Stop()
	}()

	s.start(ctx, 10*time.Second)
	log.Println("reading data from", dir+"/2000/01/02/testUUID.pcap")
	handle, err := pcap.OpenOffline(dir + "/2000/01/02/testUUID.pcap")
	rtx.Must(err, "Could not open written pcap file")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	var packets []gopacket.Packet
	for p := range ps.Packets() {
		// Verify that each packet has had its payload zeroed out.
		packets = append(packets, p)
	}
	if len(packets) != 4 {
		t.Error("Bad length (should be 4):", len(packets))
	}
	for _, p := range packets {
		al := p.ApplicationLayer()
		if al == nil {
			continue
		}
		data := al.LayerContents()
		for _, b := range data {
			if b != 0 {
				t.Error("All application layer data is supposed to be zeroed, but was not in", p)
				break
			}
		}
		srcIP := p.NetworkLayer().(*layers.IPv6).SrcIP
		for b := range srcIP[16:] {
			if b != 0 {
				t.Error("All high-end v6 address bytes should be zeroed out")
			}
		}
		dstIP := p.NetworkLayer().(*layers.IPv6).DstIP
		for b := range dstIP[16:] {
			if b != 0 {
				t.Error("All high-end v6 address bytes should be zeroed out")
			}
		}
	}
}
