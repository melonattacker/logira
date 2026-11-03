//go:build linux

package logirad

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/unix"

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

	in              chan collector.Event
	shutdownDrops   lossCounters
	drainOnce       sync.Once
	queueDrops      lossCounters
	persistFailures lossCounters
	admitMu         sync.RWMutex
	accepting       bool

	closeErr error
	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

type lossCounters struct {
	exec atomic.Uint64
	file atomic.Uint64
	net  atomic.Uint64
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
		accepting:  true,
		stopCh:     make(chan struct{}),
		stopped:    make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *session) enqueue(ev collector.Event) {
	typ := storage.EventType(ev.Type)
	if !s.enabled(typ) {
		return
	}
	s.admitMu.RLock()
	defer s.admitMu.RUnlock()
	if !s.accepting {
		s.incrementLoss(&s.shutdownDrops, typ)
		return
	}
	select {
	case s.in <- ev:
	default:
		s.incrementLoss(&s.queueDrops, typ)
	}
}

func (s *session) closeWithEnd(endTS int64, forward collector.DropCounts) error {
	s.stopOnce.Do(func() {
		s.drainAdmitted()
		if err := s.store.Flush(); err != nil {
			s.closeErr = errors.Join(s.closeErr, err)
			s.meta.Coverage.FinalizationFailures++
		}
		s.finalizeCoverage(forward)
		s.meta.EndTS = endTS
		s.meta.SuspiciousCount = s.store.SuspiciousCount()
		metaJSON, _ := json.Marshal(s.meta)
		if err := runs.WriteMeta(s.runDir, s.meta); err != nil {
			s.closeErr = errors.Join(s.closeErr, err)
			s.meta.Coverage.FinalizationFailures++
			s.finalizeCoverage(forward)
			metaJSON, _ = json.Marshal(s.meta)
		}
		if err := s.store.Close(endTS, string(metaJSON)); err != nil {
			s.closeErr = errors.Join(s.closeErr, err)
			s.meta.Coverage.FinalizationFailures++
			s.finalizeCoverage(forward)
			// SQLite may already be unavailable; preserve this failure in the
			// sidecar where possible and report it through StopRun.
			s.closeErr = errors.Join(s.closeErr, runs.WriteMeta(s.runDir, s.meta))
		}
		_ = runs.BestEffortChownTree(s.runDir, s.uid, s.gid)
	})
	return s.closeErr
}

// drainAdmitted closes admission under the enqueue lock, then consumes every
// admitted event. Routing remains registered until the manager retires it.
func (s *session) drainAdmitted() {
	s.drainOnce.Do(func() {
		s.admitMu.Lock()
		s.accepting = false
		s.admitMu.Unlock()
		close(s.stopCh)
		<-s.stopped
	})
}

func (s *session) loop() {
	defer close(s.stopped)
	for {
		select {
		case <-s.stopCh:
			for {
				select {
				case msg := <-s.in:
					s.handleEvent(msg)
				default:
					return
				}
			}
		case msg := <-s.in:
			s.handleEvent(msg)
		}
	}
}

func (s *session) handleEvent(ev collector.Event) {
	if err := s.handleObservedEvent(ev); err != nil {
		s.incrementLoss(&s.persistFailures, storage.EventType(ev.Type))
	}
}

func (s *session) handleObservedEvent(ev collector.Event) error {
	typ := storage.EventType(ev.Type)
	switch typ {
	case storage.TypeExec, storage.TypeProcess, storage.TypeFile, storage.TypeNet:
	default:
		return nil
	}
	if !s.enabled(typ) {
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
	case storage.TypeProcess:
		var d model.ProcessDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = processSummary(d)
	case storage.TypeFile:
		d, ok := s.normalizeFileDetail(ev)
		if !ok {
			return nil
		}
		if !s.shouldRetainFile(d) {
			return nil
		}
		if d.Correlation == "incomplete" {
			summary = fmt.Sprintf("file correlation incomplete syscall=%s ret=%d", d.Syscall, d.ReturnValue)
		} else if d.Op == "rename" {
			summary = fmt.Sprintf("file rename %s -> %s", d.Path, d.Path2)
		} else {
			summary = fmt.Sprintf("file %s %s", d.Op, d.Path)
		}
		attrs.Path = d.Path
		ev.Detail, _ = json.Marshal(d)
	case storage.TypeNet:
		var d model.NetDetail
		_ = json.Unmarshal(ev.Detail, &d)
		dst := strings.TrimSpace(d.DstIP)
		if d.DstPort > 0 {
			dst = net.JoinHostPort(d.DstIP, strconv.Itoa(int(d.DstPort)))
		}
		summary = fmt.Sprintf("net %s %s bytes=%d", d.Op, dst, d.Bytes)
		attrs.DstIP = d.DstIP
		attrs.DstPort = int(d.DstPort)
	}

	seq, err := s.store.AppendObserved(ts, typ, ev.PID, ev.PPID, ev.UID, summary, ev.Detail, attrs)
	if err != nil {
		return err
	}

	dets := s.evaluateDetections(typ, ev.Detail)
	return s.emitDetections(seq, dets)
}

func (s *session) enabled(typ storage.EventType) bool {
	switch typ {
	case storage.TypeExec, storage.TypeProcess:
		return s.enableExec
	case storage.TypeFile:
		return s.enableFile
	case storage.TypeNet:
		return s.enableNet
	default:
		return false
	}
}

func (s *session) incrementLoss(c *lossCounters, typ storage.EventType) {
	switch typ {
	case storage.TypeExec, storage.TypeProcess:
		c.exec.Add(1)
	case storage.TypeFile:
		c.file.Add(1)
	case storage.TypeNet:
		c.net.Add(1)
	}
}

func (s *session) finalizeCoverage(forward collector.DropCounts) {
	s.meta.Coverage.Process = s.kernelCoverage(s.enableExec, forward.Exec, s.queueDrops.exec.Load(), s.persistFailures.exec.Load())
	s.meta.Coverage.File = s.kernelCoverage(s.enableFile, forward.File, s.queueDrops.file.Load(), s.persistFailures.file.Load(), forward.FileCorrelationFailures)
	s.meta.Coverage.Network = s.kernelCoverage(s.enableNet, forward.Net, s.queueDrops.net.Load(), s.persistFailures.net.Load())
	for _, c := range []struct {
		coverage *runs.KernelCoverage
		count    uint64
	}{
		{&s.meta.Coverage.Process, s.shutdownDrops.exec.Load()},
		{&s.meta.Coverage.File, s.shutdownDrops.file.Load()},
		{&s.meta.Coverage.Network, s.shutdownDrops.net.Load()},
	} {
		c.coverage.KnownLoss.ShutdownDropped = c.count
		if c.count > 0 {
			c.coverage.Capture = "partial"
		}
	}
}

func (s *session) kernelCoverage(enabled bool, forward, queued, persist uint64, correlation ...uint64) runs.KernelCoverage {
	if !enabled {
		return runs.KernelCoverage{Availability: "unavailable", Capture: "not_applicable"}
	}
	capture := "unknown"
	var correlationFailures uint64
	if len(correlation) > 0 {
		correlationFailures = correlation[0]
	}
	if forward+queued+persist+correlationFailures > 0 || s.meta.Coverage.FinalizationFailures > 0 || s.meta.Coverage.DrainFailures > 0 {
		capture = "partial"
	}
	return runs.KernelCoverage{
		Availability: "available", Capture: capture,
		KnownLoss: runs.KnownLoss{CollectorForwardDropped: forward, SessionQueueDropped: queued, PersistenceFailures: persist, CorrelationFailures: correlationFailures},
	}
}

func (s *session) evaluateDetections(typ storage.EventType, detail json.RawMessage) []storage.Detection {
	if s.detector == nil {
		return nil
	}
	return s.detector.Evaluate(typ, detail)
}

func (s *session) emitDetections(observedSeq int64, detections []storage.Detection) error {
	for _, det := range detections {
		if _, err := s.store.AppendDetection(storage.NowUnixNanos(), det, observedSeq); err != nil {
			return err
		}
	}
	return nil
}

func (s *session) normalizeFileDetail(ev collector.Event) (model.FileDetail, bool) {
	var d model.FileDetail
	if err := json.Unmarshal(ev.Detail, &d); err != nil {
		return d, false
	}
	if d.PID <= 0 {
		d.PID = ev.PID
	}
	if d.TGID <= 0 {
		d.TGID = d.PID
	}
	if d.TID <= 0 {
		d.TID = d.PID
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

	if d.Correlation == "incomplete" {
		d.Op = "unknown"
		return d, true
	}

	rawPath := d.Path
	d.RawPath = rawPath
	resolved, resolution := s.resolveFilePath(d, rawPath, d.DirFD)
	if resolved == "" && isStateChangingFileOp(d.Op) {
		d.RawPath = rawPath
		d.Path = rawPath
		d.PathResolution = "unresolved"
		return d, true
	}
	if resolved == "" {
		return d, false
	}

	d.Path = resolved
	d.PathResolution = resolution
	if d.Path2 != "" {
		rawPath2 := d.Path2
		d.RawPath2 = rawPath2
		resolved2, resolution2 := s.resolveFilePath(d, rawPath2, d.DirFD2)
		d.Path2 = resolved2
		d.PathResolution2 = resolution2
	}
	return d, true
}

func (s *session) resolveFilePath(d model.FileDetail, p string, dirfd *int) (string, string) {
	if p == "" {
		if d.FD != nil {
			return "", "unresolved_fd"
		}
		return "", ""
	}
	if filepath.IsAbs(p) {
		if d.FD != nil && (d.Syscall == "write" || d.Syscall == "pwrite64" || d.Syscall == "writev" || d.Syscall == "ftruncate" || d.Syscall == "fchdir") {
			return p, "fd_open_path"
		}
		return p, "absolute"
	}

	if d.FD != nil && (d.Syscall == "write" || d.Syscall == "pwrite64" || d.Syscall == "writev" || d.Syscall == "ftruncate" || d.Syscall == "fchdir") {
		// This path was captured at open, possibly before chdir/rename. Never
		// rebase it against the current CWD or a reused userspace descriptor.
		return p, "unresolved_fd_open_path"
	}
	if d.TGID > 0 {
		if dirfd != nil && *dirfd >= 0 {
			procFD := fmt.Sprintf("/proc/%d/fd/%d", d.TGID, *dirfd)
			if info, err := os.Stat(procFD); err == nil && info.IsDir() {
				if base, err := os.Readlink(procFD); err == nil && filepath.IsAbs(base) {
					return strings.TrimRight(base, "/") + "/" + p, "proc_dirfd_best_effort"
				}
			}
			// A non-AT_FDCWD path cannot safely fall back to process CWD.
			return p, "unresolved_dirfd"
		}
		if dirfd == nil || *dirfd == unix.AT_FDCWD {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", d.TGID)); err == nil && cwd != "" {
				return strings.TrimRight(cwd, "/") + "/" + p, "proc_cwd_best_effort"
			}
		}
	}
	if dirfd != nil {
		return p, "unresolved_at_fdcwd"
	}
	if s.meta.Version >= 5 {
		return p, "unresolved_cwd"
	}
	// Backward compatibility for version 4 file events created before dirfd capture.
	return filepath.Join(s.meta.CWD, p), "legacy_cwd"
}

func (s *session) shouldRetainFile(d model.FileDetail) bool {
	if d.Correlation == "incomplete" || isStateChangingFileOp(d.Op) {
		return true
	}
	return s.detector != nil && s.detector.ShouldRecordFile(d)
}

func isStateChangingFileOp(op string) bool {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "create", "create_or_open", "modify", "rename", "delete", "truncate":
		return true
	default:
		return false
	}
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

func processSummary(d model.ProcessDetail) string {
	switch d.Kind {
	case "fork":
		return fmt.Sprintf("process fork tid=%d child_tid=%d", d.ParentTID, d.ChildTID)
	case "exit":
		return fmt.Sprintf("process exit tid=%d tgid=%d", d.TID, d.TGID)
	case "exec_rekey":
		return fmt.Sprintf("process exec_rekey old_pid=%d tid=%d", d.OldPID, d.TID)
	default:
		return "process " + strings.TrimSpace(d.Kind)
	}
}
