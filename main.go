package main

import (
	"context"
	"flag"
	"os"
	"sync"
	"time"

	"github.com/m-lab/go/anonymize"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/warnonerror"
	"github.com/m-lab/packet-headers/demuxer"
	"github.com/m-lab/packet-headers/tcpeventhandler"
	"github.com/m-lab/tcp-info/eventsocket"
)

var (
	dir             = flag.String("datadir", ".", "The directory to which data is written")
	eventSocket     = flag.String("eventsocket", "", "The absolute pathname of the unix-domain socket to which events will be posted.")
	captureDuration = flag.Duration("captureduration", 30*time.Second, "Only save the first captureduration of each flow, to prevent long-lived flows from spamming the hard drive.")
	flowTimeout     = flag.Duration("flowtimeout", 30*time.Second, "Once there have been no packets for a flow for at least flowtimeout, the flow can be assumed to be closed.")
	maxHeaderSize   = flag.Int("maxheadersize", 256, "The maximum size of packet headers allowed. A lower value allows the pcap process to be less wasteful but risks more esoteric IPv6 headers (which can theoretically be up to the full size of the packet but in practice seem to be under 128) getting truncated.")
	netInterface    = flag.String("interface", "eth0", "The interface on which to capture packets.")

	// Context and injected variables to allow smoke testing of main()
	mainCtx, mainCancel = context.WithCancel(context.Background())
	pcapOpenLive        = pcap.OpenLive
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from env")

	defer mainCancel()
	psrv := prometheusx.MustServeMetrics()
	defer warnonerror.Close(psrv, "Could not stop metric server")

	rtx.Must(os.Chdir(*dir), "Could not cd to directory %q", *dir)

	// A waitgroup to make sure main() doesn't exit before all its components
	// get cleaned up.
	cleanupWG := sync.WaitGroup{}

	// Get ready to save the incoming packets to files.
	dm := demuxer.New(anonymize.New(anonymize.IPAnonymizationFlag), *dir, *captureDuration)

	// Inform the demuxer of new UUIDs
	h := tcpeventhandler.New(mainCtx, dm.UUIDChan)
	cleanupWG.Add(1)
	go func() {
		eventsocket.MustRun(mainCtx, *eventSocket, h)
		cleanupWG.Done()
	}()

	// Open a packet capture
	handle, err := pcapOpenLive(*netInterface, int32(*maxHeaderSize), true, pcap.BlockForever)
	rtx.Must(err, "Could not create libpcap client")
	rtx.Must(handle.SetBPFFilter("tcp"), "Could not set up BPF filter for TCP")
	// Stop packet capture when the context is canceled.
	cleanupWG.Add(1)
	go func() {
		<-mainCtx.Done()
		handle.Close()
		cleanupWG.Done()
	}()

	// Set up the packet capture.
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)

	// Set up the timer for flow timeouts.
	flowTimeoutTicker := time.NewTicker(*flowTimeout)
	defer flowTimeoutTicker.Stop()

	// Capture packets forever, or until mainCtx is cancelled.
	dm.CapturePackets(mainCtx, packetSource.Packets(), flowTimeoutTicker.C)

	// Wait until all cleanup routines have terminated.
	cleanupWG.Wait()
}
