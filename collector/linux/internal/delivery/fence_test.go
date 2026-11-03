package delivery

import (
	"context"
	"testing"
	"time"

	collector "github.com/melonattacker/logira/collector/common"
)

func TestFlushWaitsForDeliveryAcknowledgement(t *testing.T) {
	f := New()
	out := make(chan collector.Event, 1)
	out <- collector.Event{Type: "exec"}
	flushed := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- f.Drain(ctx, func() error { close(flushed); return nil }) }()
	<-flushed
	forwarded := make(chan struct{})
	go func() { f.Forward(out); close(forwarded) }()
	if ev := <-out; ev.Type != "exec" {
		t.Fatal("barrier overtook event")
	}
	marker := <-out
	<-forwarded
	if marker.Barrier == nil {
		t.Fatal("no barrier")
	}
	select {
	case err := <-done:
		t.Fatalf("drain returned before routing: %v", err)
	default:
	}
	marker.Barrier.Acknowledge()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTimedOutFlushCannotAcknowledgeNextDrain(t *testing.T) {
	f := New()
	ctx, cancel := context.WithCancel(context.Background())
	flushed := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- f.Drain(ctx, func() error { close(flushed); return nil }) }()
	<-flushed
	cancel()
	if err := <-done; err == nil {
		t.Fatal("expected cancelled drain")
	}
	if err := f.Drain(context.Background(), func() error { t.Fatal("overlapped unresolved flush"); return nil }); err == nil {
		t.Fatal("reused pending flush")
	}
	f.Forward(make(chan collector.Event)) // canceled marker cannot block output
	fresh, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	out := make(chan collector.Event, 1)
	go func() { done <- f.Drain(fresh, func() error { go f.Forward(out); return nil }) }()
	marker := <-out
	marker.Barrier.Acknowledge()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
