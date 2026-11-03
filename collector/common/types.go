package common

import (
	"context"
	"encoding/json"
	"errors"
)

const (
	EventTypeExec    = "exec"
	EventTypeProcess = "process"
	EventTypeFile    = "file"
	EventTypeNet     = "net"
)

var ErrLinuxOnly = errors.New("logira collector is only supported on linux")

type Event struct {
	Barrier   *DeliveryBarrier `json:"-"`
	Type      string           `json:"type"`
	Timestamp string           `json:"timestamp"`
	PID       int              `json:"pid,omitempty"`
	PPID      int              `json:"ppid,omitempty"`
	UID       int              `json:"uid,omitempty"`
	Detail    json.RawMessage  `json:"detail"`
}

type Config struct {
	EnableExec   bool
	EnableFile   bool
	EnableNet    bool
	WatchPaths   []string
	ArgvMax      int
	ArgvMaxBytes int
	HashMaxBytes int64
}

type Collector interface {
	Init(ctx context.Context) error
	Start(ctx context.Context, out chan<- Event) error
	Stop(ctx context.Context) error
}

type TargetSetter interface {
	SetTargetPID(pid int)
}

type ChildWaiter interface {
	WaitForIdle(ctx context.Context) error
}

type DropCounts struct {
	Exec                    uint64
	File                    uint64
	Net                     uint64
	FileCorrelationFailures uint64
}

// LossTracker reports userspace forwarding drops for active audited cgroups.
// It does not claim visibility into losses below the collector boundary.
type LossTracker interface {
	RegisterLossTarget(cgroupID uint64)
	SnapshotAndUnregisterLossTarget(cgroupID uint64) DropCounts
}

// FileCorrelationFinalizer clears pending file syscall enters for a drained
// cgroup and reports the number that had no observed exit.
type FileCorrelationFinalizer interface {
	FinalizeFileCorrelation(cgroupID uint64) uint64
}

// DeliveryBarrier is internal queue control, never a persisted audit event.
// Forwarding must not drop it under backpressure. The daemon acknowledges it
// only after routing all preceding records from that reader.
type DeliveryBarrier struct {
	Ack  chan struct{}
	Done <-chan struct{}
}

func (b *DeliveryBarrier) Forward(out chan<- Event) {
	select {
	case out <- Event{Barrier: b}:
	case <-b.Done:
	}
}
func (b *DeliveryBarrier) Acknowledge() {
	select {
	case b.Ack <- struct{}{}:
	default:
	}
}

type DeliveryDrainer interface{ Drain(context.Context) error }

// LossSnapshotter keeps a bounded retired target observable after finalization.
type LossSnapshotter interface {
	LossTracker
	SnapshotLossTarget(cgroupID uint64) DropCounts
}
