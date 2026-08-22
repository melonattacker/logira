//go:build linux

package logirad

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/melonattacker/logira/collector"
	agentcodex "github.com/melonattacker/logira/internal/agent/codex"
	"github.com/melonattacker/logira/internal/cgroupv2"
	"github.com/melonattacker/logira/internal/detect"
	"github.com/melonattacker/logira/internal/ipc"
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

	in              chan sessionMessage
	queueDrops      lossCounters
	persistFailures lossCounters
	admitMu         sync.RWMutex
	accepting       bool
	taskCWD         map[sessionTaskIdentity]string
	latestTaskStart map[int]uint64
	fileFDPaths     map[sessionFDIdentity]string

	stopOnce sync.Once
	stopCh   chan struct{}
	stopped  chan struct{}
}

type sessionTaskIdentity struct {
	tid   int
	start uint64
}

type sessionFDIdentity struct {
	tgid int
	fd   int
}

type lossCounters struct {
	exec atomic.Uint64
	file atomic.Uint64
	net  atomic.Uint64
}

type sessionMessage struct {
	observed *collector.Event
	agent    *model.AgentDetail
	stats    *ipc.AgentTelemetryStats
	done     chan error
}

func newSession(sessionID string, uid, gid int, homeDir string, enableExec, enableFile, enableNet bool, baseDir, runDir string, meta runs.Meta, store *storage.Store, det *detect.Engine, cg *cgroupv2.Cgroup, cgroupID uint64) *session {
	s := &session{
		sessionID:       sessionID,
		uid:             uid,
		gid:             gid,
		homeDir:         homeDir,
		enableExec:      enableExec,
		enableFile:      enableFile,
		enableNet:       enableNet,
		baseDir:         baseDir,
		runDir:          runDir,
		meta:            meta,
		store:           store,
		detector:        det,
		cg:              cg,
		cgroupID:        cgroupID,
		in:              make(chan sessionMessage, 8192),
		accepting:       true,
		taskCWD:         make(map[sessionTaskIdentity]string),
		latestTaskStart: make(map[int]uint64),
		fileFDPaths:     make(map[sessionFDIdentity]string),
		stopCh:          make(chan struct{}),
		stopped:         make(chan struct{}),
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
		return
	}
	select {
	case s.in <- sessionMessage{observed: &ev}:
	default:
		s.incrementLoss(&s.queueDrops, typ)
	}
}

func (s *session) appendAgent(ctx context.Context, detail model.AgentDetail) error {
	done := make(chan error, 1)
	msg := sessionMessage{agent: &detail, done: done}
	s.admitMu.RLock()
	if !s.accepting {
		s.admitMu.RUnlock()
		return fmt.Errorf("session stopped")
	}
	select {
	case s.in <- msg:
		s.admitMu.RUnlock()
	case <-s.stopped:
		s.admitMu.RUnlock()
		return fmt.Errorf("session stopped")
	case <-ctx.Done():
		s.admitMu.RUnlock()
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-s.stopped:
		return fmt.Errorf("session stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *session) finishAgentTelemetry(ctx context.Context, stats ipc.AgentTelemetryStats) error {
	done := make(chan error, 1)
	msg := sessionMessage{stats: &stats, done: done}
	s.admitMu.RLock()
	if !s.accepting {
		s.admitMu.RUnlock()
		return fmt.Errorf("session stopped")
	}
	select {
	case s.in <- msg:
		s.admitMu.RUnlock()
	case <-s.stopped:
		s.admitMu.RUnlock()
		return fmt.Errorf("session stopped")
	case <-ctx.Done():
		s.admitMu.RUnlock()
		return ctx.Err()
	}
	select {
	case err := <-done:
		return err
	case <-s.stopped:
		return fmt.Errorf("session stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *session) closeWithEnd(endTS int64, forward collector.DropCounts) {
	s.stopOnce.Do(func() {
		s.admitMu.Lock()
		s.accepting = false
		s.admitMu.Unlock()
		close(s.stopCh)
		<-s.stopped
		s.finalizeCoverage(forward)
		s.meta.EndTS = endTS
		s.meta.SuspiciousCount = s.store.SuspiciousCount()
		metaJSON, _ := json.Marshal(s.meta)
		_ = runs.WriteMeta(s.runDir, s.meta)
		_ = s.store.Close(endTS, string(metaJSON))
		_ = runs.BestEffortChownTree(s.runDir, s.uid, s.gid)
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
					s.handleMessage(msg)
				default:
					return
				}
			}
		case msg := <-s.in:
			s.handleMessage(msg)
		}
	}
}

func (s *session) handleMessage(msg sessionMessage) {
	var err error
	switch {
	case msg.observed != nil:
		err = s.handleObservedEvent(*msg.observed)
		if err != nil {
			s.incrementLoss(&s.persistFailures, storage.EventType(msg.observed.Type))
		}
	case msg.agent != nil:
		b, marshalErr := json.Marshal(msg.agent)
		if marshalErr != nil {
			err = marshalErr
		} else {
			_, err = s.store.AppendAgent(storage.NowUnixNanos(), agentcodex.Summary(*msg.agent), b)
		}
	case msg.stats != nil:
		s.meta.Coverage.Agent = runs.AgentCoverage{
			Capture: msg.stats.Capture, Interpretation: msg.stats.Interpretation,
			LinesSeen: msg.stats.LinesSeen, LinesPersisted: msg.stats.LinesPersisted,
			Malformed: msg.stats.Malformed, UnknownSchema: msg.stats.UnknownSchema,
			RawTruncated: msg.stats.RawTruncated, AppendFailures: msg.stats.AppendFailures,
		}
	}
	if msg.done != nil {
		msg.done <- err
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
		s.observeExecContext(ev, d)
	case storage.TypeProcess:
		var d model.ProcessDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = processSummary(d)
		s.observeProcessContext(d)
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
	s.emitDetections(seq, dets)
	return nil
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

func (s *session) retainAgentWorkspaceFile(path string) bool {
	if s.meta.AgentProvider != "codex" {
		return false
	}
	root := filepath.Clean(s.meta.CWD)
	p := filepath.Clean(path)
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func (s *session) finalizeCoverage(forward collector.DropCounts) {
	s.meta.Coverage.Process = s.kernelCoverage(s.enableExec, forward.Exec, s.queueDrops.exec.Load(), s.persistFailures.exec.Load())
	s.meta.Coverage.File = s.kernelCoverage(s.enableFile, forward.File, s.queueDrops.file.Load(), s.persistFailures.file.Load(), forward.FileCorrelationFailures)
	s.meta.Coverage.Network = s.kernelCoverage(s.enableNet, forward.Net, s.queueDrops.net.Load(), s.persistFailures.net.Load())
}

func (s *session) kernelCoverage(enabled bool, forward, queued, persist uint64, correlation ...uint64) runs.KernelCoverage {
	if !enabled {
		return runs.KernelCoverage{Availability: "unavailable", Capture: "not_applicable"}
	}
	capture := "complete"
	var correlationFailures uint64
	if len(correlation) > 0 {
		correlationFailures = correlation[0]
	}
	if forward+queued+persist+correlationFailures > 0 {
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

func (s *session) emitDetections(observedSeq int64, detections []storage.Detection) {
	for _, det := range detections {
		_, _ = s.store.AppendDetection(storage.NowUnixNanos(), det, observedSeq)
	}
}

func (s *session) normalizeFileDetail(ev collector.Event) (model.FileDetail, bool) {
	s.ensureFileContext()
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
	if d.TaskStartKernelNS == 0 {
		d.TaskStartKernelNS = s.latestTaskStart[d.TID]
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

	rawPath := strings.TrimSpace(d.Path)
	resolved, resolution := s.resolveFilePath(d, rawPath, d.DirFD)
	resolved = filepath.Clean(strings.TrimSpace(resolved))
	if (resolved == "" || resolved == ".") && isStateChangingFileOp(d.Op) {
		d.RawPath = rawPath
		d.Path = rawPath
		d.PathResolution = "unresolved"
		return d, true
	}
	if resolved == "" || resolved == "." {
		return d, false
	}

	if !filepath.IsAbs(rawPath) {
		d.RawPath = rawPath
	}
	d.Path = resolved
	d.PathResolution = resolution
	if strings.TrimSpace(d.Path2) != "" {
		rawPath2 := strings.TrimSpace(d.Path2)
		resolved2, resolution2 := s.resolveFilePath(d, rawPath2, d.DirFD2)
		if !filepath.IsAbs(rawPath2) {
			d.RawPath2 = rawPath2
		}
		d.Path2 = filepath.Clean(strings.TrimSpace(resolved2))
		d.PathResolution2 = resolution2
	}
	if d.Syscall == "openat" || d.Syscall == "openat2" {
		if d.FD != nil && filepath.IsAbs(d.Path) {
			s.fileFDPaths[sessionFDIdentity{tgid: d.TGID, fd: *d.FD}] = d.Path
		}
	}
	if d.Op == "chdir" && filepath.IsAbs(d.Path) {
		s.taskCWD[sessionTaskIdentity{tid: d.TID, start: d.TaskStartKernelNS}] = d.Path
	}
	return d, true
}

func (s *session) resolveFilePath(d model.FileDetail, p string, dirfd *int) (string, string) {
	p = strings.TrimSpace(p)
	if p == "" {
		if d.FD != nil {
			return "", "unresolved_fd"
		}
		return "", ""
	}
	if filepath.IsAbs(p) {
		return p, "absolute"
	}

	if d.FD != nil && (d.Syscall == "write" || d.Syscall == "pwrite64" || d.Syscall == "writev" || d.Syscall == "ftruncate" || d.Syscall == "fchdir") {
		if resolved := s.fileFDPaths[sessionFDIdentity{tgid: d.TGID, fd: *d.FD}]; resolved != "" {
			return resolved, "fd_provenance"
		}
	}
	if d.TGID > 0 {
		if dirfd != nil && *dirfd >= 0 {
			procFD := fmt.Sprintf("/proc/%d/fd/%d", d.TGID, *dirfd)
			if info, err := os.Stat(procFD); err == nil && info.IsDir() {
				if base, err := os.Readlink(procFD); err == nil && filepath.IsAbs(base) {
					return filepath.Join(base, p), "dirfd"
				}
			}
			if resolved := s.fileFDPaths[sessionFDIdentity{tgid: d.TGID, fd: *dirfd}]; resolved != "" {
				return filepath.Join(resolved, p), "dirfd_provenance"
			}
			// A non-AT_FDCWD path cannot safely fall back to process CWD.
			return p, "unresolved_dirfd"
		}
		if dirfd == nil || *dirfd == unix.AT_FDCWD {
			if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", d.TGID)); err == nil && cwd != "" {
				return filepath.Join(cwd, p), "cwd"
			}
			identity := sessionTaskIdentity{tid: d.TID, start: d.TaskStartKernelNS}
			if cwd := s.taskCWD[identity]; cwd != "" {
				return filepath.Join(cwd, p), "task_cwd"
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

func (s *session) observeExecContext(ev collector.Event, d model.ExecDetail) {
	s.ensureFileContext()
	tid := d.TID
	if tid <= 0 {
		tid = ev.PID
	}
	if tid <= 0 {
		return
	}
	s.latestTaskStart[tid] = d.TaskStartKernelNS
	if strings.TrimSpace(d.CWD) != "" {
		s.taskCWD[sessionTaskIdentity{tid: tid, start: d.TaskStartKernelNS}] = filepath.Clean(d.CWD)
	}
}

func (s *session) observeProcessContext(d model.ProcessDetail) {
	s.ensureFileContext()
	switch d.Kind {
	case "fork":
		if d.ChildTID <= 0 {
			return
		}
		s.latestTaskStart[d.ChildTID] = d.TaskStartKernelNS
		parentStart := d.ParentTaskStartKernelNS
		if parentStart == 0 {
			parentStart = s.latestTaskStart[d.ParentTID]
		}
		if cwd := s.taskCWD[sessionTaskIdentity{tid: d.ParentTID, start: parentStart}]; cwd != "" {
			s.taskCWD[sessionTaskIdentity{tid: d.ChildTID, start: d.TaskStartKernelNS}] = cwd
		}
	case "exec_rekey":
		if d.OldPID <= 0 || d.TID <= 0 {
			return
		}
		oldIdentity := sessionTaskIdentity{tid: d.OldPID, start: d.TaskStartKernelNS}
		newIdentity := sessionTaskIdentity{tid: d.TID, start: d.TaskStartKernelNS}
		if cwd := s.taskCWD[oldIdentity]; cwd != "" {
			s.taskCWD[newIdentity] = cwd
		}
		s.latestTaskStart[d.TID] = d.TaskStartKernelNS
	}
}

func (s *session) ensureFileContext() {
	if s.taskCWD == nil {
		s.taskCWD = make(map[sessionTaskIdentity]string)
	}
	if s.latestTaskStart == nil {
		s.latestTaskStart = make(map[int]uint64)
	}
	if s.fileFDPaths == nil {
		s.fileFDPaths = make(map[sessionFDIdentity]string)
	}
}

func (s *session) shouldRetainFile(d model.FileDetail) bool {
	if s.detector != nil && s.detector.ShouldRecordFile(d) {
		return true
	}
	if s.detector != nil && d.Op == "create_or_open" {
		possibleCreate := d
		possibleCreate.Op = "create"
		if s.detector.ShouldRecordFile(possibleCreate) {
			// Preserve rule-relevant evidence without claiming that creation
			// definitely occurred or emitting a create detection.
			return true
		}
	}
	if s.meta.AgentProvider != "codex" {
		return false
	}
	if d.Correlation == "incomplete" || isStateChangingFileOp(d.Op) {
		return true
	}
	return s.retainAgentWorkspaceFile(d.Path)
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

var _ = time.Now
