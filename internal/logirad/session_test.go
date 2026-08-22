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
	s.enqueue(collector.Event{Type: collector.EventTypeFile})
	if got := s.queueDrops.exec.Load(); got != 1 {
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

func TestAgentRetentionIncludesWorkspaceOnly(t *testing.T) {
	s := &session{meta: runs.Meta{AgentProvider: "codex", CWD: "/workspace/project"}}
	if !s.retainAgentWorkspaceFile("/workspace/project/src/main.go") {
		t.Fatal("expected workspace path retained")
	}
	if s.retainAgentWorkspaceFile("/workspace/other/secret") {
		t.Fatal("unexpected path outside workspace retained")
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
