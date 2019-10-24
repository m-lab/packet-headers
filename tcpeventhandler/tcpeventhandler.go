// Package tcpeventhandler deals with the output from the eventsocket served by the tcp-info binary.
package tcpeventhandler

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"

	"github.com/google/gopacket/layers"

	"github.com/m-lab/packet-headers/demuxer"
	"github.com/m-lab/packet-headers/metrics"
	"github.com/m-lab/packet-headers/saver"

	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
)

type handler struct {
	demux *demuxer.Demuxer

	// As a general rule it is bad practice to save a context inside a struct.
	// Here we do so because Demuxer.GetSaver needs a context passed in, and
	// handler calls that function. The only other option is to plumb the
	// context through the client API, which seems wrong somehow?
	//
	// TODO: Decide whether or not to plumb the context of the
	// eventsocket.Client event loop into the eventsocket api.
	ctx context.Context

	flowsMutex sync.Mutex
	flows      map[string]demuxer.FullFlow
}

func flowFromSockID(id *inetdiag.SockID) demuxer.FullFlow {
	var ipFlow gopacket.Flow
	if strings.Contains(id.SrcIP, ":") {
		ipLayer := layers.IPv6{
			SrcIP: net.ParseIP(id.SrcIP).To16(),
			DstIP: net.ParseIP(id.DstIP).To16(),
		}
		ipFlow = ipLayer.NetworkFlow()
	} else {
		ipLayer := layers.IPv4{
			SrcIP: net.ParseIP(id.SrcIP).To4(),
			DstIP: net.ParseIP(id.DstIP).To4(),
		}
		ipFlow = ipLayer.NetworkFlow()
	}
	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(id.SPort),
		DstPort: layers.TCPPort(id.DPort),
	}
	return demuxer.FullFlow{
		IPFlow:  ipFlow,
		TCPFlow: tcpLayer.TransportFlow(),
	}
}

func (h *handler) Open(timestamp time.Time, uuid string, id *inetdiag.SockID) {
	f := flowFromSockID(id)

	h.flowsMutex.Lock()
	h.flows[uuid] = f
	h.flowsMutex.Unlock()

	s := h.demux.GetSaver(h.ctx, f)
	s.UUIDchan <- saver.UUIDEvent{UUID: uuid, Timestamp: timestamp}
}

func (h *handler) Close(timestamp time.Time, uuid string) {
	h.flowsMutex.Lock()
	f, ok := h.flows[uuid]
	if ok {
		delete(h.flows, uuid)
	}
	h.flowsMutex.Unlock()

	if ok {
		h.demux.Close(f)
	} else {
		metrics.UnknownFlowsClosed.Inc()
	}
}

// New makes a new eventsocket.Handler that informs the
func New(ctx context.Context, demux *demuxer.Demuxer) eventsocket.Handler {
	return &handler{
		demux: demux,
		ctx:   ctx,
		flows: make(map[string]demuxer.FullFlow),
	}
}
