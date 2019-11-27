package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/m-lab/go/anonymize"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/warnonerror"
	"github.com/m-lab/packet-headers/demuxer"
	"github.com/m-lab/packet-headers/muxer"
	"github.com/m-lab/packet-headers/saver"
	"github.com/m-lab/packet-headers/tcpinfohandler"
	"github.com/m-lab/tcp-info/eventsocket"
)

var (
	dir             = flag.String("datadir", ".", "The directory to which data is written")
	eventSocket     = flag.String("eventsocket", "", "The absolute pathname of the unix-domain socket to which events will be posted.")
	captureDuration = flag.Duration("captureduration", 30*time.Second, "Only save the first captureduration of each flow, to prevent long-lived flows from spamming the hard drive.")
	flowTimeout     = flag.Duration("flowtimeout", 30*time.Second, "Once there have been no packets for a flow for at least flowtimeout, the flow can be assumed to be closed.")
	maxHeaderSize   = flag.Int("maxheadersize", 256, "The maximum size of packet headers allowed. A lower value allows the pcap process to be less wasteful but risks more esoteric IPv6 headers (which can theoretically be up to the full size of the packet but in practice seem to be under 128) getting truncated.")
	sigtermWaitTime = flag.Duration("sigtermwait", 1*time.Second, "How long should the daemon hang around before exiting after receiving a SIGTERM.")

	interfaces flagx.StringArray

	// Context and injected variables to allow smoke testing of main()
	mainCtx, mainCancel = context.WithCancel(context.Background())
	pcapOpenLive        = pcap.OpenLive
)

func init() {
	flag.Var(&interfaces, "interface", "The interface on which to capture traffic. May be repeated. If unset, will capture on all available interfaces.")
}

func catch(sig os.Signal) {
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, sig)

	// Wait until we receive a signal or the context is canceled.
	select {
	case <-c:
		fmt.Println("Received", sig)
		time.Sleep(*sigtermWaitTime)
		mainCancel()
	case <-mainCtx.Done():
		fmt.Println("Canceled")
	}
}

func main() {
	defer mainCancel()

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from env")

	if saver.UUIDDelay > *captureDuration {
		rtx.Must(fmt.Errorf("Capture delay must be greater than saver.UUIDDelay: %s", saver.UUIDDelay), "")
	}

	// Special case for argument "-interface": if no specific interface was
	// specified, then "all of them" was implicitly specified. If new interfaces
	// are created after capture is started, traffic on those interfaces will be
	// ignored. If interfaces disappear, the effects are unknown. The number of
	// interfaces with a running capture is tracked in the
	// pcap_muxer_interfaces_with_captures metric.
	if len(interfaces) == 0 {
		log.Println("No interfaces specified, will listen for packets on all available interfaces.")
		ifaces, err := net.Interfaces()
		rtx.Must(err, "Could not list interfaces")
		for _, iface := range ifaces {
			interfaces = append(interfaces, iface.Name)
		}
	}

	psrv := prometheusx.MustServeMetrics()
	defer warnonerror.Close(psrv, "Could not stop metric server")

	rtx.Must(os.Chdir(*dir), "Could not cd to directory %q", *dir)

	// A waitgroup to make sure main() doesn't return before all its components
	// get cleaned up.
	cleanupWG := sync.WaitGroup{}
	defer cleanupWG.Wait()

	cleanupWG.Add(1)
	go func() {
		catch(syscall.SIGTERM)
		cleanupWG.Done()
	}()

	// Get ready to save the incoming packets to files.
	tcpdm := demuxer.NewTCP(anonymize.New(anonymize.IPAnonymizationFlag), *dir, *captureDuration)

	// Inform the demuxer of new UUIDs
	h := tcpinfohandler.New(mainCtx, tcpdm.UUIDChan)
	cleanupWG.Add(1)
	go func() {
		eventsocket.MustRun(mainCtx, *eventSocket, h)
		mainCancel()
		cleanupWG.Done()
	}()

	// A channel with a buffer to prevent tight coupling of captures with the demuxer.TCP goroutine's read loop.
	packets := make(chan gopacket.Packet, 1000)

	// Capture packets on every interface.
	cleanupWG.Add(1)
	go func() {
		muxer.MustCaptureTCPOnInterfaces(mainCtx, interfaces, packets, pcapOpenLive, int32(*maxHeaderSize))
		mainCancel()
		cleanupWG.Done()
	}()

	// Set up the timer for flow timeouts.
	flowTimeoutTicker := time.NewTicker(*flowTimeout)
	defer flowTimeoutTicker.Stop()

	// Capture packets forever, or until mainCtx is cancelled.
	tcpdm.CapturePackets(mainCtx, packets, flowTimeoutTicker.C)
}
