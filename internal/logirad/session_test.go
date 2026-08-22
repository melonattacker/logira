//go:build linux

package logirad

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func TestNormalizeFileDetail_DoesNotFilterByWatchPaths(t *testing.T) {
	s := &session{
		meta: runs.Meta{
			CWD:        "/tmp",
			WatchPaths: []string{"."},
		},
	}

	b, err := json.Marshal(model.FileDetail{
		Op:   "open",
		Path: "/home/u/.netrc",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	d, ok := s.normalizeFileDetail(collector.Event{
		PID:    1234,
		PPID:   1,
		UID:    1000,
		Detail: b,
	})
	if !ok {
		t.Fatalf("expected file detail to be accepted regardless of watch_paths")
	}
	if d.Path != "/home/u/.netrc" {
		t.Fatalf("path mismatch: got %q", d.Path)
	}
}

func TestNormalizeFileDetailResolvesRelativeOpenatAgainstDirFD(t *testing.T) {
	base := t.TempDir()
	dir, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dirfd := int(dir.Fd())
	s := &session{meta: runs.Meta{CWD: "/wrong/cwd"}}
	b, _ := json.Marshal(model.FileDetail{Op: "open", Path: "child.txt", DirFD: &dirfd})

	d, ok := s.normalizeFileDetail(collector.Event{PID: os.Getpid(), UID: os.Getuid(), Detail: b})
	if !ok {
		t.Fatal("expected relative openat event to normalize")
	}
	if want := filepath.Join(base, "child.txt"); d.Path != want {
		t.Fatalf("path=%q, want %q", d.Path, want)
	}
	if d.RawPath != "child.txt" || d.PathResolution != "dirfd" {
		t.Fatalf("resolution metadata=%+v", d)
	}
}

func TestNormalizeFileDetailDoesNotUseCWDForUnresolvedDirFD(t *testing.T) {
	badDirFD := 1 << 29
	s := &session{meta: runs.Meta{CWD: "/wrong/cwd"}}
	b, _ := json.Marshal(model.FileDetail{Op: "open", Path: "mountinfo", DirFD: &badDirFD})

	d, ok := s.normalizeFileDetail(collector.Event{PID: os.Getpid(), UID: os.Getuid(), Detail: b})
	if !ok {
		t.Fatal("expected unresolved event to remain available as evidence")
	}
	if d.Path != "mountinfo" || d.PathResolution != "unresolved_dirfd" {
		t.Fatalf("relative path was incorrectly resolved: %+v", d)
	}
}

func TestNormalizeFileDetailDoesNotResolveThroughReusableReturnedFD(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "unrelated.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fd, atFDCWD := int(f.Fd()), -100
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	s := &session{meta: runs.Meta{CWD: "/wrong/cwd"}}
	b, _ := json.Marshal(model.FileDetail{Op: "open", Path: "actual.txt", FD: &fd, DirFD: &atFDCWD})

	d, ok := s.normalizeFileDetail(collector.Event{PID: os.Getpid(), UID: os.Getuid(), Detail: b})
	if !ok || d.Path != filepath.Join(cwd, "actual.txt") || d.PathResolution != "cwd" {
		t.Fatalf("detail=%+v ok=%v", d, ok)
	}
}

func TestSessionQueueDropsOnlyEnabledStreams(t *testing.T) {
	s := &session{enableExec: true, in: make(chan sessionMessage, 1), accepting: true}
	s.enqueue(collector.Event{Type: collector.EventTypeExec})
	s.enqueue(collector.Event{Type: collector.EventTypeExec})
	s.enqueue(collector.Event{Type: collector.EventTypeProcess})
	s.enqueue(collector.Event{Type: collector.EventTypeFile})
	if got := s.queueDrops.exec.Load(); got != 2 {
		t.Fatalf("exec queue drops=%d", got)
	}
	if got := s.queueDrops.file.Load(); got != 0 {
		t.Fatalf("disabled file queue drops=%d", got)
	}
}

func TestKernelCoverageKnownLossAndDisabled(t *testing.T) {
	s := &session{}
	partial := s.kernelCoverage(true, 1, 2, 3)
	if partial.Availability != "available" || partial.Capture != "partial" || partial.KnownLoss.Total() != 6 {
		t.Fatalf("partial=%+v", partial)
	}
	complete := s.kernelCoverage(true, 0, 0, 0)
	if complete.Capture != "complete" {
		t.Fatalf("complete=%+v", complete)
	}
	disabled := s.kernelCoverage(false, 100, 100, 100)
	if disabled.Availability != "unavailable" || disabled.Capture != "not_applicable" || disabled.KnownLoss.Total() != 0 {
		t.Fatalf("disabled=%+v", disabled)
	}
}

func TestFileCorrelationFailureMakesCapturePartial(t *testing.T) {
	s := &session{}
	coverage := s.kernelCoverage(true, 0, 0, 0, 2)
	if coverage.Capture != "partial" || coverage.KnownLoss.CorrelationFailures != 2 || coverage.KnownLoss.Total() != 2 {
		t.Fatalf("coverage=%+v", coverage)
	}
}

func TestAgentRetentionIncludesWorkspaceOnly(t *testing.T) {
	s := &session{meta: runs.Meta{AgentProvider: "codex", CWD: "/workspace/project"}}
	if !s.retainAgentWorkspaceFile("/workspace/project/src/main.go") {
		t.Fatal("expected workspace path retained")
	}
	if s.retainAgentWorkspaceFile("/workspace/other/secret") {
		t.Fatal("unexpected path outside workspace retained")
	}
}

func TestAgentRetainsStateChangingAndIncompleteFileEvidence(t *testing.T) {
	s := &session{meta: runs.Meta{AgentProvider: "codex", CWD: "/workspace/project"}}
	if !s.shouldRetainFile(model.FileDetail{Op: "modify", Path: "unresolved.txt", PathResolution: "unresolved_cwd"}) {
		t.Fatal("state-changing unresolved event was dropped")
	}
	if !s.shouldRetainFile(model.FileDetail{Op: "unknown", Correlation: "incomplete"}) {
		t.Fatal("correlation uncertainty was dropped")
	}
	nonAgent := &session{meta: runs.Meta{CWD: "/workspace/project"}}
	if nonAgent.shouldRetainFile(model.FileDetail{Op: "modify", Path: "/tmp/no-rule"}) {
		t.Fatal("default non-agent retention changed")
	}
}

func TestVersion5DoesNotUseRunCWDLegacyFallback(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5, CWD: "/wrong/run/cwd"}}
	detail := model.FileDetail{TGID: 1 << 29, TID: 1 << 29}
	path, resolution := s.resolveFilePath(detail, "relative.txt", nil)
	if path != "relative.txt" || resolution != "unresolved_cwd" {
		t.Fatalf("path=%q resolution=%q", path, resolution)
	}
}

func TestForkInheritedTaskCWDResolvesAfterProcessExit(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5}}
	s.observeExecContext(collector.Event{PID: 10}, model.ExecDetail{TID: 10, TGID: 10, TaskStartKernelNS: 100, CWD: "/workspace"})
	s.observeProcessContext(model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTaskStartKernelNS: 100, ChildTID: 20, TaskStartKernelNS: 200})
	detail := model.FileDetail{TGID: 1 << 29, TID: 20, TaskStartKernelNS: 200}
	path, resolution := s.resolveFilePath(detail, "child.txt", nil)
	if path != "/workspace/child.txt" || resolution != "task_cwd" {
		t.Fatalf("path=%q resolution=%q", path, resolution)
	}
}

func TestWriteUsesSuccessfulOpenFDProvenance(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5, AgentProvider: "codex"}}
	fd, atFDCWD := 7, -100
	openRaw, _ := json.Marshal(model.FileDetail{Op: "create_or_open", Syscall: "openat", Correlation: "complete", Path: "/tmp/output.txt", FD: &fd, DirFD: &atFDCWD, TGID: 50, TID: 50})
	if _, ok := s.normalizeFileDetail(collector.Event{PID: 50, Detail: openRaw}); !ok {
		t.Fatal("open did not normalize")
	}
	writeRaw, _ := json.Marshal(model.FileDetail{Op: "modify", Syscall: "write", Correlation: "complete", Path: "output.txt", FD: &fd, DirFD: &atFDCWD, TGID: 50, TID: 50, Bytes: 3})
	write, ok := s.normalizeFileDetail(collector.Event{PID: 50, Detail: writeRaw})
	if !ok || write.Path != "/tmp/output.txt" || write.PathResolution != "fd_provenance" {
		t.Fatalf("write=%+v ok=%v", write, ok)
	}
}

func TestRenameResolvesBothDirFDPaths(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5}}
	base := t.TempDir()
	dir, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	dirfd := int(dir.Fd())
	raw, _ := json.Marshal(model.FileDetail{Op: "rename", Syscall: "renameat", Correlation: "complete", Path: "old", Path2: "new", DirFD: &dirfd, DirFD2: &dirfd, TGID: os.Getpid(), TID: os.Getpid()})
	d, ok := s.normalizeFileDetail(collector.Event{PID: os.Getpid(), Detail: raw})
	if !ok || d.Path != filepath.Join(base, "old") || d.Path2 != filepath.Join(base, "new") {
		t.Fatalf("rename=%+v ok=%v", d, ok)
	}
}

func TestExtractCgroupIDRoutesFileLifecycleEvent(t *testing.T) {
	detail, _ := json.Marshal(model.FileDetail{CgroupID: 42, Op: "modify"})
	if got := extractCgroupID(collector.EventTypeFile, detail); got != 42 {
		t.Fatalf("cgroup id=%d", got)
	}
}

func TestOrderlyCloseDrainsAdmittedMessages(t *testing.T) {
	runDir := t.TempDir()
	store, err := storage.Open(storage.OpenParams{RunID: "r", RunDir: runDir, StartTS: 1, MetaJSON: `{}`})
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("s", os.Getuid(), os.Getgid(), runDir, true, false, false, runDir, runDir,
		runs.Meta{RunID: "r", Coverage: runs.Coverage{Agent: runs.AgentCoverage{Capture: "unavailable", Interpretation: "not_applicable"}}},
		store, nil, nil, 1)
	detail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})
	for i := 0; i < 100; i++ {
		s.enqueue(collector.Event{Type: collector.EventTypeExec, PID: i + 1, Detail: detail})
	}
	s.closeWithEnd(2, collector.DropCounts{})
	events, err := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 100 {
		t.Fatalf("persisted events=%d, want 100", len(events))
	}
}

func TestPersistenceFailureIsCountedByType(t *testing.T) {
	runDir := t.TempDir()
	store, err := storage.Open(storage.OpenParams{RunID: "r", RunDir: runDir, StartTS: 1, MetaJSON: `{}`})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(2, `{}`); err != nil {
		t.Fatal(err)
	}
	s := &session{enableExec: true, store: store}
	detail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/false"})
	ev := collector.Event{Type: collector.EventTypeExec, Detail: detail}
	s.handleMessage(sessionMessage{observed: &ev})
	if got := s.persistFailures.exec.Load(); got != 1 {
		t.Fatalf("exec persistence failures=%d", got)
	}
}
