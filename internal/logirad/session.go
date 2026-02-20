//go:build linux

package logirad

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
		if s.detector != nil && !s.detector.ShouldRecordFile(d) {
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

	dets := s.evaluateDetections(typ, ev.Detail)
	s.emitDetections(seq, dets)
	return nil
}

func (s *session) evaluateDetections(typ storage.EventType, detail json.RawMessage) []storage.Detection {
	return s.detector.Evaluate(typ, detail)
}

func (s *session) emitDetections(observedSeq int64, detections []storage.Detection) {
	for _, det := range detections {
		_, _ = s.store.AppendDetection(storage.NowUnixNanos(), det, observedSeq)
	}
}

func (s *session) normalizeFileDetail(ev collector.Event) (model.FileDetail, bool) {
	var d model.FileDetail
	if err := json.Unmarshal(ev.Detail, &d); err != nil {
		return d, false
	}
	if d.PID <= 0 {
		d.PID = ev.PID
	}
	if d.UID <= 0 {
		d.UID = ev.UID
	}
	if d.PPID <= 0 {
		if ev.PPID > 0 {
			d.PPID = ev.PPID
		} else if ev.PID > 0 {
			d.PPID = logiradProcPPID(ev.PID)
		}
	}

	abs := s.resolvePath(ev.PID, d.Path)
	abs = filepath.Clean(strings.TrimSpace(abs))
	if abs == "" {
		return d, false
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

func logiradProcPPID(pid int) int {
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
