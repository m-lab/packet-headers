// Package tcpeventhandler deals with the output from the eventsocket served by the tcp-info binary.
package tcpeventhandler

import (
	"context"
	"testing"
	"time"

	"github.com/m-lab/tcp-info/inetdiag"

	"github.com/m-lab/packet-headers/demuxer"
)

func TestHandlerOpen(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := make(chan demuxer.UUIDEvent, 1)
	h := New(ctx, c)

	h.Open(time.Now(), "nildata", nil)               // No crash == success
	h.Open(time.Now(), "badips", &inetdiag.SockID{}) // No crash == success

	// Channel should be empty after the bad messages.
	select {
	case e := <-c:
		t.Errorf("Channel was supposed to be empty, but contained %+v", e)
	default:
	}

	// Now send a good message and verify that it creates a sensible UUIDEvent on the channel.
	uuid := "a_string_for_a_uuid"
	srcIP := "10.1.2.3"
	sPort := uint16(1234)
	dstIP := "11.2.3.4"
	dPort := uint16(22)
	timestamp := time.Date(2013, 11, 22, 1, 2, 3, 0, time.UTC)
	sockid := &inetdiag.SockID{
		SrcIP: srcIP,
		DstIP: dstIP,
		SPort: sPort,
		DPort: dPort,
	}

	h.Open(timestamp, uuid, sockid)
	// Read the event from the channel
	e := <-c
	if e.Timestamp != timestamp {
		t.Error("Unequal timestamps", e.Timestamp, timestamp)
	}
	if e.UUID != uuid {
		t.Error("Unequal uuids", e.UUID, uuid)
	}
}
