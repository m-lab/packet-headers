package saver

import (
	"context"
	"io/ioutil"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/m-lab/go/rtx"
)

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

func TestStatusDryRun(t *testing.T) {
	dir, err := ioutil.TempDir("", "TestStatus")
	rtx.Must(err, "Could not create tempdir")
	defer os.RemoveAll(dir)

	s := New(dir)
	tracker := statusTracker{status: s.state.Get()}
	s.state = &tracker

	s.UUIDchan <- "testUUID"
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Wait until the status is readingpackets or the surrounding context has been cancelled.
	go func() {
		for s.state.Get() != "readingpackets" && ctx.Err() == nil {
			time.Sleep(1 * time.Millisecond)
		}
		s.Stop()
	}()

	s.Start(context.Background(), 10*time.Second) // Give the disk IO 10 seconds to happen.
	expected := statusTracker{
		status: "stopped",
		past:   []string{"notstarted", "uuidwait", "filecreation", "readingpackets"},
	}
	if !reflect.DeepEqual(&tracker, &expected) {
		t.Errorf("%+v != %+v", &tracker, &expected)
	}
	if s.State() != "stopped" {
		t.Errorf("%s != 'stopped'", s.State())
	}
}
