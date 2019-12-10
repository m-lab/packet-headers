package saver

import (
	"context"
	"time"

	"github.com/m-lab/go/anonymize"
	"github.com/spf13/afero"
)

var (
	Filename             = filename
	NewPrebufferedWriter = newPrebufferedWriter
	MinInt               = minInt
	AnonymizePacket      = anonymizePacket
)

func NewTCPWithTrackerForTest(dir string, anon anonymize.IPAnonymizer, id string, fs afero.Fs, ss statusSetter, stream bool) *TCP {
	tcp := newTCP(dir, anon, id, fs, stream)
	tcp.state = ss
	return tcp
}

func (tcp *TCP) Start(ctx context.Context, uuidDelay time.Duration, duration time.Duration) {
	tcp.start(ctx, uuidDelay, duration)
}
