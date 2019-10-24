package main

import (
	"context"
	"flag"
	"os"
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
	dir         = flag.String("datadir", ".", "The directory to which data is written")
	eventSocket = flag.String("eventsocket", "", "The absolute pathname of the unix-domain socket to which events will be posted.")
	maxDuration = flag.Duration("maxduration", 30*time.Second, "Only save the first maxduration of each flow, to prevent long-lived flows from spamming the hard drive.")

	mainCtx, mainCancel = context.WithCancel(context.Background())
)

func main() {
	flag.Parse()
	rtx.Must(flagx.ArgsFromEnv(flag.CommandLine), "Could not get args from env")

	defer mainCancel()
	psrv := prometheusx.MustServeMetrics()
	defer warnonerror.Close(psrv, "Could not stop metric server")

	rtx.Must(os.Chdir(*dir), "Could not cd to directory %q", *dir)

	// Get ready to save the incoming packets to files.
	dm := demuxer.New(anonymize.New(anonymize.IPAnonymizationFlag), *dir, *maxDuration)

	// Inform the muxer of new UUIDs
	h := tcpeventhandler.New(mainCtx, dm)
	go eventsocket.MustRun(mainCtx, *eventSocket, h)

	// Open a packet capture
	// TODO: find a better value than 1600
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	rtx.Must(err, "Could not create libpcap client")
	rtx.Must(handle.SetBPFFilter("tcp"), "Could not set up BPF filter for TCP")
	// Stop packet capture when the context is canceled.
	go func() {
		<-mainCtx.Done()
		handle.Close()
	}()

	// Get the packets and fire up the Demux loop.
	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	dm.CapturePackets(mainCtx, packetSource)
}
