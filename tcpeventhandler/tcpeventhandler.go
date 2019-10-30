// Package tcpeventhandler deals with the output from the eventsocket served by the tcp-info binary.
package tcpeventhandler

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/m-lab/packet-headers/demuxer"
	"github.com/m-lab/packet-headers/metrics"
	"github.com/m-lab/tcp-info/eventsocket"
	"github.com/m-lab/tcp-info/inetdiag"
)

type handler struct {
	uuidChan chan<- demuxer.UUIDEvent

	// As a general rule it is bad practice to save a context inside a struct.
	// Here we do so because Demuxer.GetSaver needs a context passed in, and
	// handler calls that function. The only other option is to plumb the
	// context through the eventsocket client API, which seems wrong somehow?
	//
	// TODO: Decide whether or not to plumb the context of the
	// eventsocket.Client event loop into the eventsocket api.
	ctx context.Context
}

// Open processes an Open message for a new flow, sending its UUID to the demuxer.
func (h *handler) Open(timestamp time.Time, uuid string, id *inetdiag.SockID) {
	if id == nil {
		metrics.BadEventsFromTCPInfo.WithLabelValues("nilid").Inc()
		return
	}
	srcIP := net.ParseIP(id.SrcIP)
	dstIP := net.ParseIP(id.DstIP)
	if srcIP == nil || dstIP == nil {
		log.Printf("SrcIP: %s -> %s, DstIP: %s -> %s", id.SrcIP, srcIP, id.DstIP, dstIP)
		metrics.BadEventsFromTCPInfo.WithLabelValues("badip").Inc()
		return
	}
	// Can't use a struct literal here due to embedding.
	ev := demuxer.UUIDEvent{}
	ev.Flow = demuxer.FullFlowFrom4Tuple(srcIP, id.SPort, dstIP, id.DPort)
	ev.UUID = uuid
	ev.Timestamp = timestamp
	h.uuidChan <- ev
}

// Close does nothing.  Timeouts are the authoritative closing mechanism.
func (h *handler) Close(timestamp time.Time, uuid string) {
}

// New makes a new eventsocket.Handler that informs the demuxer of new flow
// creation.
func New(ctx context.Context, uuidChan chan<- demuxer.UUIDEvent) eventsocket.Handler {
	return &handler{
		uuidChan: uuidChan,
		ctx:      ctx,
	}
}
