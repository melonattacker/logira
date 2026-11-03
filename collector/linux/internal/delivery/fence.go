// Package delivery orders a ring-buffer flush marker through userspace queues.
package delivery

import (
	"context"
	"fmt"
	"sync"

	collector "github.com/melonattacker/logira/collector/common"
)

type Fence struct {
	gate    chan struct{}
	mu      sync.Mutex
	pending *collector.DeliveryBarrier
}

func New() *Fence { return &Fence{gate: make(chan struct{}, 1)} }

// Drain serializes flushes and waits for the daemon's routing acknowledgement.
// A timed-out flush cannot acknowledge a later request accidentally.
func (f *Fence) Drain(ctx context.Context, flush func() error) error {
	select {
	case f.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-f.gate }()
	b := &collector.DeliveryBarrier{Ack: make(chan struct{}, 1), Done: ctx.Done()}
	f.mu.Lock()
	if f.pending != nil {
		f.mu.Unlock()
		return fmt.Errorf("previous delivery flush is still pending")
	}
	f.pending = b
	f.mu.Unlock()
	if err := flush(); err != nil {
		f.mu.Lock()
		f.pending = nil
		f.mu.Unlock()
		return err
	}
	select {
	case <-b.Ack:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Forward is called only when the corresponding reader returns ErrFlushed.
func (f *Fence) Forward(out chan<- collector.Event) {
	f.mu.Lock()
	b := f.pending
	f.pending = nil
	f.mu.Unlock()
	if b != nil {
		b.Forward(out)
	}
}
