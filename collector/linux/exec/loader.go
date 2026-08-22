//go:build linux

package exectrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	collector "github.com/melonattacker/logira/collector/common"
	"github.com/melonattacker/logira/internal/model"
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
	TSNS                  uint64
	CgroupID              uint64
	PID                   uint32
	PPID                  uint32
	UID                   uint32
	TID                   uint32
	TGID                  uint32
	OldPID                uint32
	TaskStartKernelNS     uint64
	FirstObservedKernelNS uint64
	Comm                  [16]byte
	Filename              [maxArgBytes]byte
	Argc                  uint32
	Argv                  [maxArgs][maxArgBytes]byte
}

type rawProcessEvent struct {
	TSNS                    uint64
	CgroupID                uint64
	TaskStartKernelNS       uint64
	ParentTaskStartKernelNS uint64
	FirstObservedKernelNS   uint64
	Kind                    uint32
	TID                     uint32
	TGID                    uint32
	ParentTID               uint32
	ParentTGID              uint32
	ChildTID                uint32
	ChildTGID               uint32
	OldPID                  uint32
}

type Tracer struct {
	cfg Config

	mu            sync.Mutex
	coll          *ebpf.Collection
	links         []link.Link
	reader        *ringbuf.Reader
	processReader *ringbuf.Reader
	out           chan collector.Event
	runWG         sync.WaitGroup
	started       bool
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

	objPath := getenvAny("LOGIRA_EXEC_BPF_OBJ", "logira_EXEC_BPF_OBJ")
	if objPath == "" {
		tried := defaultObjCandidates()
		objPath = firstExistingPath(tried...)
		if objPath == "" {
			return nil, fmt.Errorf(
				"exec bpf object not found (tried %s). Run `make generate` to create it, or set LOGIRA_EXEC_BPF_OBJ to an existing .o",
				strings.Join(tried, ", "),
			)
		}
	} else {
		if _, err := os.Stat(objPath); err != nil {
			return nil, fmt.Errorf("exec bpf object %s: %w", objPath, err)
		}
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
	processEventsMap, ok := coll.Maps["process_events"]
	if !ok {
		_ = rdr.Close()
		coll.Close()
		return nil, fmt.Errorf("process events map not found")
	}
	processRdr, err := ringbuf.NewReader(processEventsMap)
	if err != nil {
		_ = rdr.Close()
		coll.Close()
		return nil, fmt.Errorf("new process ringbuf reader: %w", err)
	}

	attach := []struct {
		group string
		name  string
		prog  string
	}{
		{"sched", "sched_process_exec", "trace_sched_exec"},
		{"sched", "sched_process_fork", "trace_sched_fork"},
		{"sched", "sched_process_exit", "trace_sched_exit"},
		{"syscalls", "sys_enter_execve", "trace_enter_execve"},
		{"syscalls", "sys_enter_execveat", "trace_enter_execveat"},
	}

	links := make([]link.Link, 0, len(attach))
	for _, a := range attach {
		prog, ok := coll.Programs[a.prog]
		if !ok {
			_ = rdr.Close()
			_ = processRdr.Close()
			coll.Close()
			return nil, fmt.Errorf("exec program %s not found", a.prog)
		}
		lnk, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			for _, l := range links {
				_ = l.Close()
			}
			_ = rdr.Close()
			_ = processRdr.Close()
			coll.Close()
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", a.group, a.name, err)
		}
		links = append(links, lnk)
	}

	out := make(chan collector.Event, 2048)
	t.coll = coll
	t.links = links
	t.reader = rdr
	t.processReader = processRdr
	t.out = out
	t.started = true

	t.runWG.Add(2)
	go func() {
		defer t.runWG.Done()
		t.consumeExec(ctx, out)
	}()
	go func() {
		defer t.runWG.Done()
		t.consumeProcess(ctx, out)
	}()
	go func() {
		t.runWG.Wait()
		close(out)
	}()

	return out, nil
}

func (t *Tracer) consumeExec(ctx context.Context, out chan<- collector.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
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
			Filename:              cString(raw.Filename[:]),
			Argv:                  argv,
			Comm:                  cString(raw.Comm[:]),
			KernelTimeNS:          raw.TSNS,
			TID:                   int(raw.TID),
			TGID:                  int(raw.TGID),
			OldPID:                int(raw.OldPID),
			TaskStartKernelNS:     raw.TaskStartKernelNS,
			FirstObservedKernelNS: raw.FirstObservedKernelNS,
			CgroupID:              raw.CgroupID,
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

func (t *Tracer) consumeProcess(ctx context.Context, out chan<- collector.Event) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		rec, err := t.processReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}

		var raw rawProcessEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		kind := processKind(raw.Kind)
		if kind == "" {
			continue
		}
		detail := model.ProcessDetail{
			Kind:                    kind,
			TID:                     int(raw.TID),
			TGID:                    int(raw.TGID),
			ParentTID:               int(raw.ParentTID),
			ParentTGID:              int(raw.ParentTGID),
			ChildTID:                int(raw.ChildTID),
			ChildTGID:               int(raw.ChildTGID),
			OldPID:                  int(raw.OldPID),
			TaskStartKernelNS:       raw.TaskStartKernelNS,
			ParentTaskStartKernelNS: raw.ParentTaskStartKernelNS,
			FirstObservedKernelNS:   raw.FirstObservedKernelNS,
			KernelTimeNS:            raw.TSNS,
			CgroupID:                raw.CgroupID,
		}
		if kind == "fork" {
			detail.CloneKind = "unknown"
		}
		if kind == "exit" {
			detail.GroupDead = "unknown"
		}
		if kind == "fork" && raw.ChildTGID != 0 {
			if raw.ChildTGID == raw.ParentTGID {
				detail.CloneKind = "thread_clone"
			} else {
				detail.CloneKind = "process_fork"
			}
		}
		b, err := json.Marshal(detail)
		if err != nil {
			continue
		}
		pid := int(raw.TGID)
		ppid := 0
		if kind == "fork" {
			pid = int(raw.ChildTID)
			ppid = int(raw.ParentTGID)
		}
		out <- collector.Event{
			Type:      collector.EventTypeProcess,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			PID:       pid,
			PPID:      ppid,
			Detail:    b,
		}
	}
}

func processKind(kind uint32) string {
	switch kind {
	case 1:
		return "fork"
	case 2:
		return "exit"
	case 3:
		return "exec_rekey"
	default:
		return ""
	}
}

func (t *Tracer) Stop(ctx context.Context) error {
	t.mu.Lock()
	if !t.started {
		t.mu.Unlock()
		return nil
	}
	reader := t.reader
	processReader := t.processReader
	links := append([]link.Link{}, t.links...)
	coll := t.coll
	t.started = false
	t.mu.Unlock()

	if reader != nil {
		_ = reader.Close()
	}
	if processReader != nil {
		_ = processReader.Close()
	}
	for _, l := range links {
		_ = l.Close()
	}
	if coll != nil {
		coll.Close()
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
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func getenvAny(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func defaultObjCandidates() []string {
	rel := []string{
		filepath.Join("collector", "linux", "exec", "trace_bpfel.o"),
		filepath.Join("collector", "linux", "exec", "trace.bpf.o"),
		filepath.Join("exec", "trace_bpfel.o"),
		filepath.Join("exec", "trace.bpf.o"),
		"trace_bpfel.o",
		"trace.bpf.o",
	}

	out := make([]string, 0, len(rel)*3+2)
	out = append(out, rel...)

	// Package-local absolute path works in `go test` where CWD can be package-scoped.
	if _, file, _, ok := runtime.Caller(0); ok {
		dir := filepath.Dir(file)
		out = append(out,
			filepath.Join(dir, "trace_bpfel.o"),
			filepath.Join(dir, "trace.bpf.o"),
		)
	}

	// Executable-relative paths help systemd/install layouts.
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, p := range rel {
			out = append(out, filepath.Join(exeDir, p))
		}
	}

	return uniquePaths(out)
}

func uniquePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
