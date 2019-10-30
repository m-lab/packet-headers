package main

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/m-lab/go/prometheusx"

	"github.com/google/gopacket/pcap"
	"github.com/m-lab/go/rtx"
	"github.com/m-lab/tcp-info/eventsocket"
)

func fakePcapOpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (*pcap.Handle, error) {
	return pcap.OpenOffline("testdata/v6.pcap")
}

func TestMainSmokeTest(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestMainSmokeTest")
	rtx.Must(err, "Could not create temp dir")
	defer os.RemoveAll(dir)

	// Set up a tcpinfo service. Don't use mainCtx for it because if the socket
	// goes away while main() is running then main() (correctly) crashes. We
	// don't want the exit of main() to race with the termination of this
	// server.
	tcpiCtx, tcpiCancel := context.WithCancel(context.Background())
	defer tcpiCancel()
	*eventSocket = dir + "/tcpevents.sock"
	tcpi := eventsocket.New(*eventSocket)
	tcpi.Listen()
	go tcpi.Serve(tcpiCtx)

	// Wait until the eventsocket appears.
	for _, err := os.Stat(*eventSocket); err != nil; _, err = os.Stat(*eventSocket) {
	}

	// Tests are unlikely to have enough privileges to open packet captures, so
	// use a fake version that reads from one of our testfiles.
	pcapOpenLive = fakePcapOpenLive
	go func() {
		time.Sleep(1)
		mainCancel()
	}()

	// Listen on any port for metrics.
	*prometheusx.ListenAddress = ":0"
	main()
	// No crash and successful termination == success
}
