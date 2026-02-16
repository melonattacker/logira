//go:build linux

package filetrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	collector "github.com/melonattacker/logira/collector/common"
	"github.com/melonattacker/logira/internal/model"
)

const maxPathLen = 256

type rawFileEvent struct {
	TSNS     uint64
	CgroupID uint64
	PID      uint32
	UID      uint32
	Flags    uint32
	FD       int32
	Filename [maxPathLen]byte
}

type Tracer struct {
	mu      sync.Mutex
	coll    *ebpf.Collection
	links   []link.Link
	reader  *ringbuf.Reader
	out     chan collector.Event
	runWG   sync.WaitGroup
	started bool
}

func NewTracer() *Tracer { return &Tracer{} }

func (t *Tracer) Init(ctx context.Context) error {
	_ = ctx
	return nil
}

func (t *Tracer) Start(ctx context.Context) (<-chan collector.Event, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return nil, fmt.Errorf("file tracer already started")
	}

	objPath := getenvAny("LOGIRA_FILE_BPF_OBJ")
	if objPath == "" {
		tried := defaultObjCandidates("filetrace")
		objPath = firstExistingPath(tried...)
		if objPath == "" {
			return nil, fmt.Errorf(
				"file bpf object not found (tried %s). Run `make generate` to create it, or set LOGIRA_FILE_BPF_OBJ to an existing .o",
				strings.Join(tried, ", "),
			)
		}
	} else if _, err := os.Stat(objPath); err != nil {
		return nil, fmt.Errorf("file bpf object %s: %w", objPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load file bpf object %s: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new file bpf collection: %w", err)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("file events map not found")
	}
	rdr, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("new file ringbuf reader: %w", err)
	}

	attach := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_openat", "trace_enter_openat"},
		{"syscalls", "sys_exit_openat", "trace_exit_openat"},
		{"syscalls", "sys_enter_openat2", "trace_enter_openat2"},
		{"syscalls", "sys_exit_openat2", "trace_exit_openat2"},
	}

	links := make([]link.Link, 0, len(attach))
	for _, a := range attach {
		prog, ok := coll.Programs[a.prog]
		if !ok {
			rdr.Close()
			coll.Close()
			return nil, fmt.Errorf("file program %s not found", a.prog)
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
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			continue
		}

		var raw rawFileEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		op := opFromFlags(raw.Flags)
		if op == "" {
			continue
		}

		detail := model.FileDetail{
			Op:       op,
			Path:     cString(raw.Filename[:]),
			CgroupID: raw.CgroupID,
		}
		b, err := json.Marshal(detail)
		if err != nil {
			continue
		}

		out <- collector.Event{
			Type:      collector.EventTypeFile,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			PID:       int(raw.PID),
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
	}
	return nil
}

func opFromFlags(flags uint32) string {
	// Minimal interpretation: treat create as create, any write access as modify.
	const (
		oWRONLY = 1
		oRDWR   = 2
		oCREAT  = 0x40
		oTRUNC  = 0x200
	)
	if flags&oCREAT != 0 {
		return "create"
	}
	if flags&(oWRONLY|oRDWR|oTRUNC) != 0 {
		return "modify"
	}
	return ""
}
