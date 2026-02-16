//go:build linux

package logirad

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/cgroupv2"
	"github.com/melonattacker/logira/internal/detect"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type session struct {
	sessionID string
	uid       int
	gid       int
	homeDir   string

	enableExec bool
	enableFile bool
	enableNet  bool

	baseDir string
	runDir  string
	meta    runs.Meta

	store    *storage.Store
	detector *detect.Engine

	cg       *cgroupv2.Cgroup
	cgroupID uint64

	in chan collector.Event

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

func newSession(sessionID string, uid, gid int, homeDir string, enableExec, enableFile, enableNet bool, baseDir, runDir string, meta runs.Meta, store *storage.Store, det *detect.Engine, cg *cgroupv2.Cgroup, cgroupID uint64) *session {
	s := &session{
		sessionID:  sessionID,
		uid:        uid,
		gid:        gid,
		homeDir:    homeDir,
		enableExec: enableExec,
		enableFile: enableFile,
		enableNet:  enableNet,
		baseDir:    baseDir,
		runDir:     runDir,
		meta:       meta,
		store:      store,
		detector:   det,
		cg:         cg,
		cgroupID:   cgroupID,
		in:         make(chan collector.Event, 8192),
		stopCh:     make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *session) enqueue(ev collector.Event) {
	select {
	case s.in <- ev:
	default:
		// Drop under backpressure.
	}
}

func (s *session) closeWithEnd(endTS int64, metaJSON []byte) {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		<-s.stopped
		_ = s.store.Close(endTS, string(metaJSON))
		_ = runs.BestEffortChownTree(s.runDir, s.uid, s.gid)
	})
}

func (s *session) loop() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stopCh:
			return
		case ev := <-s.in:
			_ = s.handleObservedEvent(ev)
		}
	}
}

func (s *session) handleObservedEvent(ev collector.Event) error {
	typ := storage.EventType(ev.Type)
	switch typ {
	case storage.TypeExec, storage.TypeFile, storage.TypeNet:
	default:
		return nil
	}
	if typ == storage.TypeExec && !s.enableExec {
		return nil
	}
	if typ == storage.TypeFile && !s.enableFile {
		return nil
	}
	if typ == storage.TypeNet && !s.enableNet {
		return nil
	}

	ts := storage.NowUnixNanos()
	var summary string
	var attrs storage.EventRow

	switch typ {
	case storage.TypeExec:
		var d model.ExecDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = execSummary(d)
		attrs.Exe = d.Filename
	case storage.TypeFile:
		d, ok := s.normalizeFileDetail(ev)
		if !ok {
			return nil
		}
		summary = fmt.Sprintf("file %s %s", d.Op, d.Path)
		attrs.Path = d.Path
		ev.Detail, _ = json.Marshal(d)
	case storage.TypeNet:
		var d model.NetDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = fmt.Sprintf("net %s %s:%d bytes=%d", d.Op, d.DstIP, d.DstPort, d.Bytes)
		attrs.DstIP = d.DstIP
		attrs.DstPort = int(d.DstPort)
	}

	seq, err := s.store.AppendObserved(ts, typ, ev.PID, ev.PPID, ev.UID, summary, ev.Detail, attrs)
	if err != nil {
		return err
	}

	for _, det := range s.detector.Evaluate(typ, ev.Detail) {
		_, _ = s.store.AppendDetection(storage.NowUnixNanos(), det, seq)
	}
	return nil
}

func (s *session) normalizeFileDetail(ev collector.Event) (model.FileDetail, bool) {
	var d model.FileDetail
	if err := json.Unmarshal(ev.Detail, &d); err != nil {
		return d, false
	}

	// Watch paths filter: keep volume bounded like the legacy watcher.
	abs := s.resolvePath(ev.PID, d.Path)
	abs = filepath.Clean(strings.TrimSpace(abs))
	if abs == "" {
		return d, false
	}

	if len(s.meta.WatchPaths) > 0 {
		ok := false
		for _, w := range s.meta.WatchPaths {
			wp := strings.TrimSpace(w)
			if wp == "" {
				continue
			}
			if !filepath.IsAbs(wp) {
				wp = filepath.Join(s.meta.CWD, wp)
			}
			wp = filepath.Clean(wp)
			if wp == abs || strings.HasPrefix(abs, wp+string(os.PathSeparator)) {
				ok = true
				break
			}
		}
		if !ok {
			return d, false
		}
	}

	d.Path = abs
	return d, true
}

func (s *session) resolvePath(pid int, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return p
	}
	// Best-effort: openat relative paths should be resolved using /proc/<pid>/cwd.
	if pid > 0 {
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil && cwd != "" {
			return filepath.Join(cwd, p)
		}
	}
	return filepath.Join(s.meta.CWD, p)
}

func execSummary(d model.ExecDetail) string {
	if len(d.Argv) > 0 {
		head := d.Argv
		if len(head) > 3 {
			head = head[:3]
		}
		return "exec " + strings.Join(head, " ")
	}
	if d.Filename != "" {
		return "exec " + d.Filename
	}
	return "exec <unknown>"
}

var _ = context.Background
var _ = time.Now
