package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/m-lab/go/anonymize"
	"github.com/m-lab/go/bytecount"
	"github.com/m-lab/go/flagx"
	"github.com/m-lab/go/prometheusx"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/go/warnonerror"
	"github.com/m-lab/packet-headers/demuxer"
	"github.com/m-lab/packet-headers/muxer"
	"github.com/m-lab/packet-headers/tcpinfohandler"
	"github.com/m-lab/tcp-info/eventsocket"
)

var (
	dir              = flag.String("datadir", ".", "The directory to which data is written")
	captureDuration  = flag.Duration("captureduration", 30*time.Second, "Only save the first captureduration of each flow, to prevent long-lived flows from spamming the hard drive.")
	uuidWaitDuration = flag.Duration("uuidwaitduration", 5*time.Second, "Wait up to uuidwaitduration for each flow before either assigning a UUID or discarding all future packets. This prevents buffering unsaveable packets.")
	flowTimeout      = flag.Duration("flowtimeout", 30*time.Second, "Once there have been no packets for a flow for at least flowtimeout, the flow can be assumed to be closed.")
	maxHeaderSize    = flag.Int("maxheadersize", 256, "The maximum size of packet headers allowed. A lower value allows the pcap process to be less wasteful but risks more esoteric IPv6 headers (which can theoretically be up to the full size of the packet but in practice seem to be under 128) getting truncated.")
	sigtermWaitTime  = flag.Duration("sigtermwait", 1*time.Second, "How long should the daemon hang around before exiting after receiving a SIGTERM.")
	streamToDisk     = flag.Bool("stream", false, "Stream results to disk instead of buffering them in RAM.")
	maxFlows         = flag.Int("maxflows", 0, "The maximum number of concurrent flows allowed. When this threshold is reached, new flows will be ignored.")

	maxIdleRAM = 3 * bytecount.Gigabyte
	maxHeap    = 8 * bytecount.Gigabyte

	interfaces flagx.StringArray

	// Context and injected variables to allow smoke testing of main()
	mainCtx, mainCancel = context.WithCancel(context.Background())
	pcapOpenLive        = pcap.OpenLive
)

func init() {
	flag.Var(&interfaces, "interface", "The interface on which to capture traffic. May be repeated. If unset, will capture on all available interfaces.")
	flag.Var(&maxIdleRAM, "maxidleram", "How much idle RAM we should tolerate before we try and forcibly return it to the OS.")
	flag.Var(&maxHeap, "maxheap", "Stop collecting traces once process uses more than this amount of RAM.")
	log.SetFlags(log.Lshortfile | log.LstdFlags)
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

var netInterfaces = net.Interfaces

func processFlags() ([]net.Interface, error) {
	// Verify that capture duration is always longer than uuid wait duration.
	if *uuidWaitDuration > *captureDuration {
		return nil, fmt.Errorf("capture duration must be greater than UUID wait duration: %s vs %s",
			*captureDuration, *uuidWaitDuration)
	}

	// Special case for argument "-interface": if no specific interface was
	// explicitly specified, then "all of them" was implicitly specified. If new
	// interfaces are created after capture is started, traffic on those
	// interfaces will be ignored. If interfaces disappear, the effects are
	// unknown. The number of interfaces with a running capture is tracked in
	// the pcap_muxer_interfaces_with_captures metric.
	if len(interfaces) == 0 {
		log.Println("No interfaces specified, will listen for packets on all available interfaces.")
		return netInterfaces()
	}
	ifaces := []net.Interface{}
	for _, iface := range interfaces {
		i, err := net.InterfaceByName(iface)
		if err != nil {
			return ifaces, err
		}
		ifaces = append(ifaces, *i)
	}
	return ifaces, nil
}

func filterUpInterfaces(ifaces []net.Interface) []net.Interface {
	result := []net.Interface{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp != 0 {
			// We can only capture packets from interfaces that are up.
			result = append(result, iface)
		}
	}
	return result
}

func main() {
	defer mainCancel()

	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from env")
	ifaces, err := processFlags()
	rtx.Must(err, "Failed to process flags")

	// Create the data directory. This will be a no-op if it already exists.
	if *dir != "" {
		rtx.PanicOnError(os.MkdirAll(*dir, 0775), "Could not create the data dir %s", *dir)
	}

	psrv := prometheusx.MustServeMetrics()
	defer warnonerror.Close(psrv, "Could not stop metric server")

	rtx.Must(os.Chdir(*dir), "Could not cd to directory %q", *dir)

	// Set a memory limit for the GC to keep RAM used below maxHeap bytes. This
	// is a soft limit that will alter how the GC behaves (e.g. reclaiming more
	// frequently, releasing RAM back to the OS) but will not stop RAM usage by
	// the process.
	debug.SetMemoryLimit(int64(maxHeap))

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
	tcpdm := demuxer.NewTCP(
		anonymize.New(anonymize.IPAnonymizationFlag), *dir, *uuidWaitDuration,
		*captureDuration, maxIdleRAM, *streamToDisk, uint64(maxHeap), *maxFlows)

	// Inform the demuxer of new UUIDs
	h := tcpinfohandler.New(mainCtx, tcpdm.UUIDChan)
	cleanupWG.Add(1)
	go func() {
		eventsocket.MustRun(mainCtx, *eventsocket.Filename, h)
		mainCancel()
		cleanupWG.Done()
	}()

	// A channel with a buffer to prevent tight coupling of captures with the demuxer.TCP goroutine's read loop.
	packets := make(chan gopacket.Packet, 1000)

	// Capture packets on every interface.
	cleanupWG.Add(1)
	go func() {
		muxer.MustCaptureTCPOnInterfaces(mainCtx, filterUpInterfaces(ifaces), packets, pcapOpenLive, int32(*maxHeaderSize))
		mainCancel()
		cleanupWG.Done()
	}()

	// Set up the timer for flow timeouts.
	flowTimeoutTicker := time.NewTicker(*flowTimeout)
	defer flowTimeoutTicker.Stop()

	// Capture packets forever, or until mainCtx is cancelled.
	tcpdm.CapturePackets(mainCtx, packets, flowTimeoutTicker.C)
}
