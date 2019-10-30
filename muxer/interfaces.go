package muxer

import (
	"context"
	"sync"

	"github.com/google/gopacket"
)

func forwardPackets(ctx context.Context, in <-chan gopacket.Packet, out chan<- gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case p, ok := <-in:
			if !ok {
				return
			}
			out <- p
		case <-ctx.Done():
			return
		}
	}
}

// MuxPackets causes every packet on every input channel to be sent to the output channel.
func MuxPackets(ctx context.Context, in []<-chan gopacket.Packet, out chan<- gopacket.Packet) {
	wg := sync.WaitGroup{}
	for _, inC := range in {
		wg.Add(1)
		go forwardPackets(ctx, inC, out, &wg)
	}

	wg.Wait()
	close(out)
}
