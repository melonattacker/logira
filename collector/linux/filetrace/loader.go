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
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	collector "github.com/melonattacker/logira/collector/common"
	"github.com/melonattacker/logira/internal/model"
)

const maxPathLen = 256

type rawFileEvent struct {
	TSNS        uint64
	CgroupID    uint64
	EnterTSNS   uint64
	TGID        uint32
	TID         uint32
	UID         uint32
	Kind        uint32
	Syscall     uint32
	Flags       uint32
	FD          int32
	DirFD       int32
	DirFD2      int32
	Pad1        int32
	ReturnValue int64
	Correlation uint8
	Pad2        [7]byte
	Path        [maxPathLen]byte
	Path2       [maxPathLen]byte
}

type rawPendingFileOp struct {
	CgroupID  uint64
	EnterTSNS uint64
	Kind      uint32
	Syscall   uint32
	TGID      uint32
	TID       uint32
	UID       uint32
	Flags     uint32
	FD        int32
	DirFD     int32
	DirFD2    int32
	Pad1      uint32
	Path      [maxPathLen]byte
	Path2     [maxPathLen]byte
}

type rawFDPathKey struct {
	CgroupID uint64
	TGID     uint32
	FD       int32
}

type rawFDPathValue struct {
	DirFD int32
	Flags uint32
	Path  [maxPathLen]byte
}

type rawFileStageCounters struct {
	Enters                uint64
	Exits                 uint64
	Emitted               uint64
	RingDrops             uint64
	MissingEnters         uint64
	FailedExits           uint64
	PendingUpdateFailures uint64
	UnattributedWrites    uint64
}

// StageCounters expose each diagnostic boundary without changing event
// retention. BPF counters are system-wide while a tracer is attached.
type StageCounters struct {
	BPFEnters                uint64
	BPFExits                 uint64
	BPFEmitted               uint64
	BPFRingDrops             uint64
	BPFMissingEnters         uint64
	BPFFailedExits           uint64
	BPFPendingUpdateFailures uint64
	BPFUnattributedWrites    uint64
	RingSamples              uint64
	Decoded                  uint64
	DecodeFailures           uint64
}

type Tracer struct {
	mu             sync.Mutex
	coll           *ebpf.Collection
	links          []link.Link
	reader         *ringbuf.Reader
	out            chan collector.Event
	runWG          sync.WaitGroup
	ringSamples    atomic.Uint64
	decoded        atomic.Uint64
	decodeFailures atomic.Uint64
	started        bool
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
		{"syscalls", "sys_enter_write", "trace_enter_write"},
		{"syscalls", "sys_exit_write", "trace_exit_write"},
		{"syscalls", "sys_enter_pwrite64", "trace_enter_pwrite64"},
		{"syscalls", "sys_exit_pwrite64", "trace_exit_pwrite64"},
		{"syscalls", "sys_enter_writev", "trace_enter_writev"},
		{"syscalls", "sys_exit_writev", "trace_exit_writev"},
		{"syscalls", "sys_enter_rename", "trace_enter_rename"},
		{"syscalls", "sys_exit_rename", "trace_exit_rename"},
		{"syscalls", "sys_enter_renameat", "trace_enter_renameat"},
		{"syscalls", "sys_exit_renameat", "trace_exit_renameat"},
		{"syscalls", "sys_enter_renameat2", "trace_enter_renameat2"},
		{"syscalls", "sys_exit_renameat2", "trace_exit_renameat2"},
		{"syscalls", "sys_enter_unlink", "trace_enter_unlink"},
		{"syscalls", "sys_exit_unlink", "trace_exit_unlink"},
		{"syscalls", "sys_enter_unlinkat", "trace_enter_unlinkat"},
		{"syscalls", "sys_exit_unlinkat", "trace_exit_unlinkat"},
		{"syscalls", "sys_enter_truncate", "trace_enter_truncate"},
		{"syscalls", "sys_exit_truncate", "trace_exit_truncate"},
		{"syscalls", "sys_enter_ftruncate", "trace_enter_ftruncate"},
		{"syscalls", "sys_exit_ftruncate", "trace_exit_ftruncate"},
		{"syscalls", "sys_enter_chdir", "trace_enter_chdir"},
		{"syscalls", "sys_exit_chdir", "trace_exit_chdir"},
		{"syscalls", "sys_enter_fchdir", "trace_enter_fchdir"},
		{"syscalls", "sys_exit_fchdir", "trace_exit_fchdir"},
		{"syscalls", "sys_enter_close", "trace_enter_close"},
		{"syscalls", "sys_exit_close", "trace_exit_close"},
	}

	links := make([]link.Link, 0, len(attach))
	for _, a := range attach {
		prog, ok := coll.Programs[a.prog]
		if !ok {
			_ = rdr.Close()
			coll.Close()
			return nil, fmt.Errorf("file program %s not found", a.prog)
		}
		lnk, err := link.Tracepoint(a.group, a.name, prog, nil)
		if err != nil {
			for _, l := range links {
				_ = l.Close()
			}
			_ = rdr.Close()
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
		t.ringSamples.Add(1)

		raw, err := decodeFileEvent(rec.RawSample)
		if err != nil {
			t.decodeFailures.Add(1)
			continue
		}
		t.decoded.Add(1)

		op := opFromRaw(raw)
		if op == "" {
			continue
		}

		fd, dirfd := int(raw.FD), int(raw.DirFD)
		detail := model.FileDetail{
			Op:           op,
			Syscall:      syscallName(raw.Syscall),
			Correlation:  correlationName(raw.Correlation),
			Path:         cString(raw.Path[:]),
			Path2:        cString(raw.Path2[:]),
			Flags:        raw.Flags,
			ReturnValue:  raw.ReturnValue,
			PID:          int(raw.TGID),
			TID:          int(raw.TID),
			TGID:         int(raw.TGID),
			UID:          int(raw.UID),
			KernelTimeNS: raw.TSNS,
			CgroupID:     raw.CgroupID,
		}
		if raw.Kind == 2 && raw.ReturnValue > 0 {
			detail.Bytes = raw.ReturnValue
		}
		if raw.FD >= 0 {
			detail.FD = &fd
		}
		if raw.Correlation == 1 {
			detail.DirFD = &dirfd
			if raw.Kind == 3 {
				dirfd2 := int(raw.DirFD2)
				detail.DirFD2 = &dirfd2
			}
		}
		b, err := json.Marshal(detail)
		if err != nil {
			continue
		}

		out <- collector.Event{
			Type:      collector.EventTypeFile,
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			PID:       int(raw.TGID),
			UID:       int(raw.UID),
			Detail:    b,
		}
	}
}

func decodeFileEvent(sample []byte) (rawFileEvent, error) {
	var raw rawFileEvent
	const want = 592
	if len(sample) != want {
		return raw, fmt.Errorf("file event size %d, want %d", len(sample), want)
	}
	if err := binary.Read(bytes.NewReader(sample), binary.LittleEndian, &raw); err != nil {
		return raw, err
	}
	return raw, nil
}

func (t *Tracer) Stats() StageCounters {
	out := StageCounters{RingSamples: t.ringSamples.Load(), Decoded: t.decoded.Load(), DecodeFailures: t.decodeFailures.Load()}
	t.mu.Lock()
	coll := t.coll
	t.mu.Unlock()
	if coll == nil {
		return out
	}
	m := coll.Maps["stage_counters"]
	if m == nil {
		return out
	}
	var perCPU []rawFileStageCounters
	key := uint32(0)
	if err := m.Lookup(&key, &perCPU); err != nil {
		return out
	}
	for _, raw := range perCPU {
		out.BPFEnters += raw.Enters
		out.BPFExits += raw.Exits
		out.BPFEmitted += raw.Emitted
		out.BPFRingDrops += raw.RingDrops
		out.BPFMissingEnters += raw.MissingEnters
		out.BPFFailedExits += raw.FailedExits
		out.BPFPendingUpdateFailures += raw.PendingUpdateFailures
		out.BPFUnattributedWrites += raw.UnattributedWrites
	}
	return out
}

// FinalizeCgroup deletes pending enter states after the audited cgroup has
// drained. Each removed state is a known missing-exit correlation failure.
func (t *Tracer) FinalizeCgroup(cgroupID uint64) uint64 {
	if cgroupID == 0 {
		return 0
	}
	t.mu.Lock()
	coll := t.coll
	t.mu.Unlock()
	if coll == nil {
		return 0
	}
	pending := coll.Maps["pending_file_ops"]
	if pending == nil {
		return 0
	}
	var count uint64
	var key uint32
	var value rawPendingFileOp
	iter := pending.Iterate()
	for iter.Next(&key, &value) {
		if value.CgroupID == cgroupID {
			if err := pending.Delete(&key); err == nil {
				count++
			}
		}
	}
	if fdPaths := coll.Maps["fd_paths"]; fdPaths != nil {
		var fdKey rawFDPathKey
		var fdValue rawFDPathValue
		iter := fdPaths.Iterate()
		for iter.Next(&fdKey, &fdValue) {
			if fdKey.CgroupID == cgroupID {
				_ = fdPaths.Delete(&fdKey)
			}
		}
	}
	return count
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
	// Minimal interpretation: create beats modify, modify beats open(read-only).
	const (
		oCREAT = 0x40
		oEXCL  = 0x80
		oTRUNC = 0x200
	)
	if flags&oCREAT != 0 && flags&oEXCL != 0 {
		return "create"
	}
	if flags&oCREAT != 0 {
		return "create_or_open"
	}
	if flags&oTRUNC != 0 {
		return "modify"
	}
	return "open"
}

func opFromRaw(raw rawFileEvent) string {
	if raw.Correlation == 2 {
		return "unknown"
	}
	switch raw.Kind {
	case 1:
		return opFromFlags(raw.Flags)
	case 2, 5:
		return "modify"
	case 3:
		return "rename"
	case 4:
		return "delete"
	case 6:
		return "chdir"
	default:
		return ""
	}
}

func correlationName(value uint8) string {
	if value == 1 {
		return "complete"
	}
	return "incomplete"
}

func syscallName(value uint32) string {
	names := [...]string{"", "openat", "openat2", "write", "pwrite64", "writev", "rename", "renameat", "renameat2", "unlink", "unlinkat", "truncate", "ftruncate", "chdir", "fchdir", "close"}
	if int(value) >= len(names) {
		return "unknown"
	}
	return names[value]
}
