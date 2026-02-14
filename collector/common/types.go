package common

import (
	"context"
	"encoding/json"
	"errors"
)

const (
	EventTypeExec = "exec"
	EventTypeFile = "file"
	EventTypeNet  = "net"
)

var ErrLinuxOnly = errors.New("logira collector is only supported on linux")

type Event struct {
	Type      string          `json:"type"`
	Timestamp string          `json:"timestamp"`
	PID       int             `json:"pid,omitempty"`
	PPID      int             `json:"ppid,omitempty"`
	UID       int             `json:"uid,omitempty"`
	Detail    json.RawMessage `json:"detail"`
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
