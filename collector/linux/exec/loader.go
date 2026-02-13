//go:build linux

package exectrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/melonattacker/agentlogix/collector"
	"github.com/melonattacker/agentlogix/internal/model"
)

const (
	maxArgs     = 20
	maxArgBytes = 256
)

type Config struct {
	ArgvMax      int
	ArgvMaxBytes int
}

type rawExecEvent struct {
	TSNS     uint64
	PID      uint32
	PPID     uint32
	UID      uint32
	Comm     [16]byte
	Filename [maxArgBytes]byte
	Argc     uint32
	Argv     [maxArgs][maxArgBytes]byte
}

type Tracer struct {
	cfg Config

	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	out     chan collector.Event
	runWG   sync.WaitGroup
	started bool
}

func NewTracer(cfg Config) *Tracer {
	if cfg.ArgvMax <= 0 {
		cfg.ArgvMax = maxArgs
	}
	if cfg.ArgvMaxBytes <= 0 {
		cfg.ArgvMaxBytes = maxArgBytes
	}
	return &Tracer{cfg: cfg}
}

func (t *Tracer) Init(ctx context.Context) error {
	_ = ctx
	return nil
}

func (t *Tracer) Start(ctx context.Context) (<-chan collector.Event, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return nil, fmt.Errorf("exec tracer already started")
	}

	objPath := os.Getenv("AGENTLOGIX_EXEC_BPF_OBJ")
	if objPath == "" {
		objPath = firstExistingPath(
			filepath.Join("collector", "linux", "exec", "trace_bpfel.o"),
			filepath.Join("collector", "linux", "exec", "trace.bpf.o"),
		)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load exec bpf object %s: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new exec bpf collection: %w", err)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("exec events map not found")
	}
	rdr, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("new exec ringbuf reader: %w", err)
	}

	attach := []struct {
		group string
		name  string
		prog  string
	}{
		{"sched", "sched_process_exec", "trace_sched_exec"},
		{"syscalls", "sys_enter_execve", "trace_enter_execve"},
		{"syscalls", "sys_enter_execveat", "trace_enter_execveat"},
	}

	links := make([]link.Link, 0, len(attach))
	for _, a := range attach {
		prog, ok := coll.Programs[a.prog]
		if !ok {
			rdr.Close()
			coll.Close()
			return nil, fmt.Errorf("exec program %s not found", a.prog)
		}
		lnk, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			for _, l := range links {
				_ = l.Close()
			}
			rdr.Close()
			coll.Close()
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", a.group, a.name, err)
		}
		links = append(links, lnk)
	}

	out := make(chan collector.Event, 2048)
	t.coll = coll
	t.links = links
	t.reader = rdr
	t.out = out
	t.started = true

	t.runWG.Add(1)
	go func() {
		defer t.runWG.Done()
		defer close(out)
		t.consume(ctx, out)
	}()

	return out, nil
}

func (t *Tracer) consume(ctx context.Context, out chan<- collector.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := t.reader.Read()
		if err != nil {
			if ringbuf.IsClosed(err) || ctx.Err() != nil {
				return
			}
			continue
		}

		var raw rawExecEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		argc := int(raw.Argc)
		if argc > t.cfg.ArgvMax {
			argc = t.cfg.ArgvMax
		}
		argv := make([]string, 0, argc)
		for i := 0; i < argc && i < maxArgs; i++ {
			arg := cString(raw.Argv[i][:])
			if len(arg) > t.cfg.ArgvMaxBytes {
				arg = arg[:t.cfg.ArgvMaxBytes]
			}
			if arg == "" {
				continue
			}
			argv = append(argv, arg)
		}

		detail := model.ExecDetail{
			Filename:     cString(raw.Filename[:]),
			Argv:         argv,
			Comm:         cString(raw.Comm[:]),
			KernelTimeNS: raw.TSNS,
		}
		b, err := json.Marshal(detail)
		if err != nil {
			continue
		}

		out <- collector.Event{
			Type:      collector.EventTypeExec,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			PID:       int(raw.PID),
			PPID:      int(raw.PPID),
			UID:       int(raw.UID),
			Detail:    b,
		}
	}
}

func (t *Tracer) Stop(ctx context.Context) error {
	t.mu.Lock()
	if !t.started {
		t.mu.Unlock()
		return nil
	}
	reader := t.reader
	links := append([]link.Link{}, t.links...)
	coll := t.coll
	t.started = false
	t.mu.Unlock()

	if reader != nil {
		_ = reader.Close()
	}
	for _, l := range links {
		_ = l.Close()
	}
	if coll != nil {
		_ = coll.Close()
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		t.runWG.Wait()
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func cString(b []byte) string {
	for i := range b {
		if b[i] == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func firstExistingPath(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return paths[0]
}
