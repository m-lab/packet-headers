package saver_test

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/m-lab/packet-headers/saver"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/rtx"
	"github.com/spf13/afero"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func TestMinInt(t *testing.T) {
	for _, c := range []struct{ x, y, want int }{
		{1, 0, 0},
		{1, 1, 1},
		{0, 1, 0},
		{0, 0, 0},
	} {
		if saver.MinInt(c.x, c.y) != c.want {
			t.Errorf("Bad minInt (%+v)", c)
		}
	}
}

func TestAnonymizationWontCrashOnNil(t *testing.T) {
	a := anonymize.New(anonymize.Netblock)

	// Try to anonymize packets with no IP data.
	saver.AnonymizePacket(a, nil) // No crash == success
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
	saver.AnonymizePacket(a, ethOnlyPacket) // No crash == success

	// All other cases are tested by the TestSaverWithRealv4Data and
	// TestSaverWithRealv6Data cases later.
}

type statusTracker struct {
	status string
	past   []string
	mu     sync.Mutex
}

func (s *statusTracker) Set(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func TestPrebufferedWriter(t *testing.T) {
	pw := saver.NewPrebufferedWriter()
	err := pw.Redirect(nil)
	if err != os.ErrInvalid {
		t.Error("Should return ErrInvalid on nil writer", err)
	}
}

func TestSaverDryRun(t *testing.T) {
	fs := afero.NewMemMapFs()
	dir, err := afero.TempDir(fs, "", "TestSaverDryRun")
	rtx.Must(err, "Could not create tempdir")

	tracker := statusTracker{status: "notstarted"}
	s := saver.NewTCPWithTrackerForTest(dir, anonymize.New(anonymize.None), "TestSaverDryRun", fs, &tracker, true)

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)

	// Send a UUID but never send any packets.
	s.UUIDchan <- saver.UUIDEvent{UUID: "testUUID", Timestamp: tstamp}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Wait until the status is readingcandidatepackets or the surrounding context has been cancelled.
	go func() {
		for tracker.Get() != "readingcandidatepackets" && ctx.Err() == nil {
			time.Sleep(1 * time.Millisecond)
		}
		cancel()
	}()

	s.Start(ctx, 5*time.Millisecond, 10*time.Millisecond) // Give the disk IO 10 seconds to happen.
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "readingcandidatepackets", "nopacketserror", "discardingpackets"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

func TestSaverWithUUID(t *testing.T) {
	// For this one, use the real filesystem, even though we don't write anything to it.
	dir, err := ioutil.TempDir("", "TestSaverWithUUID")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	tracker := statusTracker{status: "notstarted"}
	fs := afero.NewOsFs()
	s := saver.NewTCPWithTrackerForTest(dir, anonymize.New(anonymize.None), "TestSaverWithUUID", fs, &tracker, true)

	h, err := pcap.OpenOffline("../testdata/v4.pcap")
	rtx.Must(err, "Could not open v4.pcap")
	ps := gopacket.NewPacketSource(h, h.LinkType())
	var packets []gopacket.Packet
	for p := range ps.Packets() {
		packets = append(packets, p)
	}
	// Send first half of packets.
	for i := 0; i < len(packets)/2; i++ {
		s.Pchan <- packets[i]
	}
	// Send a UUID.
	s.UUIDchan <- saver.UUIDEvent{UUID: "testUUID", Timestamp: time.Now()}

	// Run saver in background.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	go func() {
		defer cancel()
		s.Start(ctx, 100*time.Millisecond, 2*time.Second)
	}()

	// Wait for 2x UUID wait duration to move to the second read/save loop.
	time.Sleep(200 * time.Millisecond)
	for i := len(packets) / 2; i < len(packets); i++ {
		s.Pchan <- packets[i]
	}
	// Close channel saver is using, so that it stops.
	close(s.Pchan)
	// Wait until ctx is canceled.
	<-ctx.Done()

	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writepartial", "streaming", "discardingpackets"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}

type limFile struct {
	afero.File
	numWritesRemaining int
}

func (lf *limFile) Write(s []byte) (int, error) {
	if lf.numWritesRemaining > 0 {
		log.Println("Writing", len(s))
		lf.numWritesRemaining--
		return lf.File.Write(s)
	}
	log.Println("failing write")
	return 0, afero.ErrFileClosed
}

type limFs struct {
	afero.Fs
	mkdirOutcome error
	openOutcome  error
	writeLim     int
}

func (fs *limFs) MkdirAll(name string, perm os.FileMode) error {
	if fs.mkdirOutcome != nil {
		return fs.mkdirOutcome
	}
	return fs.Fs.MkdirAll(name, perm)
}

func (fs *limFs) OpenFile(name string, flag int, perm os.FileMode) (afero.File, error) {
	if fs.openOutcome != nil {
		return nil, fs.openOutcome
	}

	f, err := fs.Fs.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	lf := limFile{
		File:               f,
		numWritesRemaining: fs.writeLim,
	}
	return &lf, nil
}

func TestSaverVariousErrors(t *testing.T) {
	tests := []struct {
		name           string
		lfs            afero.Fs
		uuid           string
		closeUUID      bool
		pcap           string
		expectedStates []string
		stream         bool
	}{
		{
			name: "fail no uuid, open channel",
			lfs:  &limFs{afero.NewMemMapFs(), os.ErrPermission, nil, 0},
			uuid: "", closeUUID: false,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidtimedouterror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail no uuid, closed channel",
			lfs:  &limFs{afero.NewMemMapFs(), os.ErrPermission, nil, 0},
			uuid: "", closeUUID: true,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidchanclosederror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail on mkdir",
			lfs:  &limFs{afero.NewMemMapFs(), os.ErrPermission, nil, 0},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "mkdirerror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail on file open (with streaming)",
			lfs:  &limFs{afero.NewMemMapFs(), nil, os.ErrPermission, 0},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writepartial", "fileopenerror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail on file open (no streaming)",
			lfs:  &limFs{afero.NewMemMapFs(), nil, os.ErrPermission, 0},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writefinal", "fileopenerror", "discardingpackets"},
			stream:         false,
		},
		{
			name: "fail after uuid",
			lfs:  &limFs{afero.NewMemMapFs(), nil, nil, 0},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v4.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writepartial", "writepartialerror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail after partial (streaming)",
			lfs:  &limFs{afero.NewMemMapFs(), nil, nil, 1},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v6.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writepartial", "streaming", "streamingerror", "discardingpackets"},
			stream:         true,
		},
		{
			name: "fail after partial (no streaming)",
			lfs:  &limFs{afero.NewMemMapFs(), nil, nil, 0},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/v6.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writefinal", "writefinalerror", "discardingpackets"},
			stream:         false,
		},
		{
			// This large file currently results in about 50 to 60 writes, but we only allow 5 writes to succeed.
			// Note that this depends on how the zip package behaves.  If it buffers larger amounts of data, then
			// this will behave differently.
			name: "large, for coverage",
			lfs:  &limFs{afero.NewMemMapFs(), nil, nil, 5},
			uuid: "testUUID", closeUUID: true,
			pcap:           "../testdata/large-ndt.pcap",
			expectedStates: []string{"notstarted", "readingcandidatepackets", "uuidwait", "uuidfound", "dircreation", "writepartial", "streaming", "streamingerror", "discardingpackets"},
			stream:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, err := afero.TempDir(tt.lfs, "", "TestSaver")
			rtx.Must(err, "Could not create tempdir")

			tracker := statusTracker{status: "notstarted"}
			s := saver.NewTCPWithTrackerForTest(dir, anonymize.New(anonymize.None), "TestSaverCantStream", tt.lfs, &tracker, tt.stream)

			// Get the packet data ready to send.
			h, err := pcap.OpenOffline(tt.pcap)
			rtx.Must(err, fmt.Sprint("Could not open", tt.pcap))
			ps := gopacket.NewPacketSource(h, h.LinkType())

			if len(tt.uuid) > 0 {
				s.UUIDchan <- saver.UUIDEvent{UUID: "test/UUID", Timestamp: time.Now()}
			}
			packets := 0
			for p := range ps.Packets() {
				packets++
				s.Pchan <- p
			}
			log.Println("Total of", packets, "packets")
			if tt.closeUUID {
				close(s.UUIDchan)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			s.Start(ctx, 20*time.Millisecond, 80*time.Millisecond)

			expected := statusTracker{
				status: "stopped",
				past:   tt.expectedStates,
			}
			if !reflect.DeepEqual(&tracker, &expected) {
				t.Errorf("%+v != %+v", &tracker, &expected)
			}
			if s.State() != "stopped" {
				t.Errorf("%s != 'stopped'", s.State())
			}
		})
	}

}

func TestSaverWithRealv4Data(t *testing.T) {
	fs := afero.NewMemMapFs()
	dir, err := afero.TempDir(fs, "", "TestSaverWithRealv4Data")
	rtx.Must(err, "Could not create tempdir")

	// Send a UUID and then some packets.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := saver.StartNew(ctx, anonymize.New(anonymize.Netblock), dir, 5*time.Second, 10*time.Second, "TestSaverWithRealv4Data", true)

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)
	s.UUIDchan <- saver.UUIDEvent{UUID: "testUUID", Timestamp: tstamp}

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

	log.Println("reading data from", dir+"/2000/01/02/testUUID.pcap.gz")
	rtx.Must(exec.Command("gunzip", dir+"/2000/01/02/testUUID.pcap.gz").Run(), "Could not unzip")

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
	fs := afero.NewMemMapFs()
	dir, err := afero.TempDir(fs, "", "TestSaverWithRealv6Data")
	rtx.Must(err, "Could not create tempdir")

	// Send a UUID and then some packets.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	s := saver.StartNew(ctx, anonymize.New(anonymize.Netblock), dir, 5*time.Second, 10*time.Second, "TestSaverWithRealv6Data", false)

	tstamp := time.Date(2000, 1, 2, 3, 4, 5, 6, time.UTC)
	s.UUIDchan <- saver.UUIDEvent{UUID: "testUUID", Timestamp: tstamp}

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
	rtx.Must(exec.Command("gunzip", dir+"/2000/01/02/testUUID.pcap.gz").Run(), "Could not unzip")
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
