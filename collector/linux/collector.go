//go:build linux

package linuxcollector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/rlimit"
	collector "github.com/melonattacker/logira/collector/common"
	exectrace "github.com/melonattacker/logira/collector/linux/exec"
	filetrace "github.com/melonattacker/logira/collector/linux/filetrace"
	nettrace "github.com/melonattacker/logira/collector/linux/net"
)

type LinuxCollector struct {
	cfg collector.Config

	execTracer *exectrace.Tracer
	netTracer  *nettrace.Tracer
	fileTracer *filetrace.Tracer

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewCollector(cfg collector.Config) *LinuxCollector {
	if cfg.ArgvMax <= 0 {
		cfg.ArgvMax = 20
	}
	if cfg.ArgvMaxBytes <= 0 {
		cfg.ArgvMaxBytes = 256
	}
	if cfg.HashMaxBytes <= 0 {
		cfg.HashMaxBytes = 10 * 1024 * 1024
	}
	if len(cfg.WatchPaths) == 0 {
		cfg.WatchPaths = []string{"."}
	}

	return &LinuxCollector{cfg: cfg}
}

func (lc *LinuxCollector) Init(ctx context.Context) error {
	if lc.cfg.EnableExec || lc.cfg.EnableNet || lc.cfg.EnableFile {
		// eBPF map creation is constrained by RLIMIT_MEMLOCK on many systems.
		// This typically requires root or CAP_SYS_RESOURCE.
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("remove memlock rlimit (try sudo): %w", err)
		}
	}

	if lc.cfg.EnableExec {
		lc.execTracer = exectrace.NewTracer(exectrace.Config{ArgvMax: lc.cfg.ArgvMax, ArgvMaxBytes: lc.cfg.ArgvMaxBytes})
		if err := lc.execTracer.Init(ctx); err != nil {
			return fmt.Errorf("init exec tracer: %w", err)
		}
	}
	if lc.cfg.EnableNet {
		lc.netTracer = nettrace.NewTracer()
		if err := lc.netTracer.Init(ctx); err != nil {
			return fmt.Errorf("init net tracer: %w", err)
		}
	}
	if lc.cfg.EnableFile {
		lc.fileTracer = filetrace.NewTracer()
		if err := lc.fileTracer.Init(ctx); err != nil {
			return fmt.Errorf("init file tracer: %w", err)
		}
	}
	return nil
}

func (lc *LinuxCollector) Start(ctx context.Context, out chan<- collector.Event) error {
	runCtx, cancel := context.WithCancel(ctx)
	lc.cancel = cancel

	if lc.execTracer != nil {
		execCh, err := lc.execTracer.Start(runCtx)
		if err != nil {
			cancel()
			return err
		}
		lc.wg.Add(1)
		go func() {
			defer lc.wg.Done()
			for ev := range execCh {
				lc.handleEvent(out, ev)
			}
		}()
	}

	if lc.netTracer != nil {
		netCh, err := lc.netTracer.Start(runCtx)
		if err != nil {
			cancel()
			if lc.execTracer != nil {
				_ = lc.execTracer.Stop(context.Background())
			}
			return err
		}
		lc.wg.Add(1)
		go func() {
			defer lc.wg.Done()
			for ev := range netCh {
				lc.handleEvent(out, ev)
			}
		}()
	}

	if lc.fileTracer != nil {
		fileCh, err := lc.fileTracer.Start(runCtx)
		if err != nil {
			cancel()
			if lc.execTracer != nil {
				_ = lc.execTracer.Stop(context.Background())
			}
			if lc.netTracer != nil {
				_ = lc.netTracer.Stop(context.Background())
			}
			return err
		}
		lc.wg.Add(1)
		go func() {
			defer lc.wg.Done()
			for ev := range fileCh {
				lc.handleEvent(out, ev)
			}
		}()
	}

	return nil
}

func (lc *LinuxCollector) Stop(ctx context.Context) error {
	if lc.cancel != nil {
		lc.cancel()
	}

	var errs []error
	// Stop underlying readers first so their output channels close and the
	// forwarding goroutines in lc.wg can exit without deadlocking.
	if lc.execTracer != nil {
		if err := lc.execTracer.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if lc.netTracer != nil {
		if err := lc.netTracer.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if lc.fileTracer != nil {
		if err := lc.fileTracer.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		lc.wg.Wait()
	}()

	select {
	case <-ctx.Done():
		errs = append(errs, ctx.Err())
	case <-done:
	}
	return errors.Join(errs...)
}

func (lc *LinuxCollector) SetTargetPID(pid int) {
	// No-op in daemon mode. Kept for backward compatibility with older tests/callers.
	_ = pid
}

func (lc *LinuxCollector) WaitForIdle(ctx context.Context) error {
	_ = ctx
	return nil
}

func (lc *LinuxCollector) handleEvent(out chan<- collector.Event, ev collector.Event) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if ev.Type == collector.EventTypeExec {
		if ev.PPID <= 0 && ev.PID > 0 {
			ev.PPID = procPPID(ev.PID)
		}
		ev = lc.enrichExecCWD(ev)
	}

	select {
	case out <- ev:
	default:
		// Drop under backpressure.
	}
}

func (lc *LinuxCollector) enrichExecCWD(ev collector.Event) collector.Event {
	if ev.Type != collector.EventTypeExec || ev.PID <= 0 {
		return ev
	}

	var detail map[string]any
	if err := json.Unmarshal(ev.Detail, &detail); err != nil {
		return ev
	}
	if _, ok := detail["cwd"]; ok {
		return ev
	}

	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", ev.PID))
	if err != nil {
		return ev
	}
	if rel, rerr := filepath.Rel(".", cwd); rerr == nil && !strings.HasPrefix(rel, "..") {
		cwd = rel
	}
	detail["cwd"] = cwd
	b, err := json.Marshal(detail)
	if err != nil {
		return ev
	}
	ev.Detail = b
	return ev
}

func procPPID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	s := string(b)
	r := strings.LastIndex(s, ")")
	if r == -1 || r+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[r+2:])
	if len(fields) < 3 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}
