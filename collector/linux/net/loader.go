//go:build linux

package nettrace

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	collector "github.com/melonattacker/agentlogix/collector/common"
	"github.com/melonattacker/agentlogix/internal/model"
)

type rawNetEvent struct {
	TSNS     uint64
	CgroupID uint64
	PID      uint32
	UID      uint32
	Op       uint8
	Proto    uint8
	Pad1     uint16
	IP4      uint32
	Port     uint16
	Pad2     uint16
	Bytes    int64
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

func NewTracer() *Tracer {
	return &Tracer{}
}

func (t *Tracer) Init(ctx context.Context) error {
	_ = ctx
	return nil
}

func (t *Tracer) Start(ctx context.Context) (<-chan collector.Event, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.started {
		return nil, fmt.Errorf("net tracer already started")
	}

	objPath := os.Getenv("AGENTLOGIX_NET_BPF_OBJ")
	if objPath == "" {
		tried := []string{
			filepath.Join("collector", "linux", "net", "trace_bpfel.o"),
			filepath.Join("collector", "linux", "net", "trace.bpf.o"),
		}
		objPath = firstExistingPath(tried...)
		if objPath == "" {
			return nil, fmt.Errorf(
				"net bpf object not found (tried %s). Run `make generate` to create it, or set AGENTLOGIX_NET_BPF_OBJ to an existing .o",
				strings.Join(tried, ", "),
			)
		}
	} else {
		if _, err := os.Stat(objPath); err != nil {
			return nil, fmt.Errorf("net bpf object %s: %w", objPath, err)
		}
	}

	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, fmt.Errorf("load net bpf object %s: %w", objPath, err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new net bpf collection: %w", err)
	}

	eventsMap, ok := coll.Maps["events"]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("net events map not found")
	}
	rdr, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("new net ringbuf reader: %w", err)
	}

	attach := []struct {
		group string
		name  string
		prog  string
	}{
		{"syscalls", "sys_enter_connect", "trace_enter_connect"},
		{"syscalls", "sys_exit_connect", "trace_exit_connect"},
		{"syscalls", "sys_enter_sendto", "trace_enter_sendto"},
		{"syscalls", "sys_exit_sendto", "trace_exit_sendto"},
		{"syscalls", "sys_enter_sendmsg", "trace_enter_sendmsg"},
		{"syscalls", "sys_exit_sendmsg", "trace_exit_sendmsg"},
		{"syscalls", "sys_enter_recvfrom", "trace_enter_recvfrom"},
		{"syscalls", "sys_exit_recvfrom", "trace_exit_recvfrom"},
		{"syscalls", "sys_enter_recvmsg", "trace_enter_recvmsg"},
		{"syscalls", "sys_exit_recvmsg", "trace_exit_recvmsg"},
	}

	links := make([]link.Link, 0, len(attach))
	for _, a := range attach {
		prog, ok := coll.Programs[a.prog]
		if !ok {
			for _, l := range links {
				_ = l.Close()
			}
			rdr.Close()
			coll.Close()
			return nil, fmt.Errorf("net program %s not found", a.prog)
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

		var raw rawNetEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		detail := model.NetDetail{
			Op:       opName(raw.Op),
			Proto:    protoName(raw.Proto),
			DstIP:    ipv4String(raw.IP4),
			DstPort:  raw.Port,
			Bytes:    raw.Bytes,
			CgroupID: raw.CgroupID,
		}
		b, err := json.Marshal(detail)
		if err != nil {
			continue
		}

		out <- collector.Event{
			Type:      collector.EventTypeNet,
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
		return nil
	}
}

func opName(op uint8) string {
	switch op {
	case 1:
		return "connect"
	case 2:
		return "send"
	case 3:
		return "recv"
	default:
		return "unknown"
	}
}

func protoName(proto uint8) string {
	switch proto {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}

func ipv4String(ip uint32) string {
	if ip == 0 {
		return ""
	}
	b := []byte{byte(ip), byte(ip >> 8), byte(ip >> 16), byte(ip >> 24)}
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
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
