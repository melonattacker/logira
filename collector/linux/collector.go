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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/melonattacker/agentlogix/collector"
	exectrace "github.com/melonattacker/agentlogix/collector/linux/exec"
	filewatcher "github.com/melonattacker/agentlogix/collector/linux/file"
	nettrace "github.com/melonattacker/agentlogix/collector/linux/net"
)

type LinuxCollector struct {
	cfg collector.Config

	execTracer  *exectrace.Tracer
	netTracer   *nettrace.Tracer
	fileWatcher *filewatcher.Watcher

	rootPID atomic.Int32

	mu      sync.Mutex
	tracked map[int]struct{}

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

	return &LinuxCollector{cfg: cfg, tracked: make(map[int]struct{})}
}

func (lc *LinuxCollector) Init(ctx context.Context) error {
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
		lc.fileWatcher = filewatcher.NewWatcher(filewatcher.Config{WatchPaths: lc.cfg.WatchPaths, HashMaxBytes: lc.cfg.HashMaxBytes})
		if err := lc.fileWatcher.Init(ctx); err != nil {
			return fmt.Errorf("init file watcher: %w", err)
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

	if lc.fileWatcher != nil {
		fileCh, err := lc.fileWatcher.Start(runCtx)
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

	done := make(chan struct{})
	go func() {
		defer close(done)
		lc.wg.Wait()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
	}

	var errs []error
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
	if lc.fileWatcher != nil {
		if err := lc.fileWatcher.Stop(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (lc *LinuxCollector) SetTargetPID(pid int) {
	if pid <= 0 {
		return
	}
	lc.rootPID.Store(int32(pid))
	lc.trackPID(pid)
}

func (lc *LinuxCollector) WaitForIdle(ctx context.Context) error {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()

	for {
		if lc.activeTrackedCount() == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (lc *LinuxCollector) handleEvent(out chan<- collector.Event, ev collector.Event) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if ev.PID > 0 && !lc.isRelevantPID(ev.PID) {
		return
	}

	if ev.Type == collector.EventTypeExec {
		if ev.PPID <= 0 && ev.PID > 0 {
			ev.PPID = procPPID(ev.PID)
		}
		ev = lc.enrichExecCWD(ev)
		if ev.PID > 0 {
			lc.trackPID(ev.PID)
		}
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

func (lc *LinuxCollector) trackPID(pid int) {
	if pid <= 0 {
		return
	}
	lc.mu.Lock()
	lc.tracked[pid] = struct{}{}
	lc.mu.Unlock()
}

func (lc *LinuxCollector) isRelevantPID(pid int) bool {
	if pid <= 0 {
		return true
	}
	lc.mu.Lock()
	_, ok := lc.tracked[pid]
	lc.mu.Unlock()
	if ok {
		return true
	}

	root := int(lc.rootPID.Load())
	if root <= 0 {
		return false
	}

	chain, isChild := isDescendantOf(pid, root)
	if isChild {
		lc.mu.Lock()
		for _, p := range chain {
			lc.tracked[p] = struct{}{}
		}
		lc.mu.Unlock()
	}
	return isChild
}

func (lc *LinuxCollector) activeTrackedCount() int {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	count := 0
	for pid := range lc.tracked {
		if processAlive(pid) {
			count++
			continue
		}
		delete(lc.tracked, pid)
	}
	return count
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func isDescendantOf(pid, root int) ([]int, bool) {
	if pid <= 0 || root <= 0 {
		return nil, false
	}
	chain := []int{pid}
	seen := map[int]struct{}{pid: {}}
	cur := pid
	for i := 0; i < 128; i++ {
		if cur == root {
			return chain, true
		}
		ppid := procPPID(cur)
		if ppid <= 0 || ppid == cur {
			return nil, false
		}
		if _, dup := seen[ppid]; dup {
			return nil, false
		}
		seen[ppid] = struct{}{}
		chain = append(chain, ppid)
		cur = ppid
	}
	return nil, false
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
