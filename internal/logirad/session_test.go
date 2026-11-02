//go:build linux

package logirad

import (
	"encoding/json"
	"github.com/melonattacker/logira/internal/detect"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	dir, err := os.Open(base) //nolint:gosec // Path returned by t.TempDir(), not user input.
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()
	dirfd := int(dir.Fd()) //nolint:gosec // Successfully opened Linux file descriptors fit in int.
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
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close file: %v", err)
		}
	}()
	fd, atFDCWD := int(f.Fd()), -100 //nolint:gosec // Successfully opened Linux file descriptors fit in int.
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
	s := &session{enableExec: true, in: make(chan collector.Event, 1), accepting: true}
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
	if complete.Capture != "unknown" {
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

func TestOrdinaryRunRetainsStateChangingAndIncompleteFileEvidence(t *testing.T) {
	s := &session{meta: runs.Meta{CWD: "/workspace/project"}}
	if !s.shouldRetainFile(model.FileDetail{Op: "modify", Path: "unresolved.txt", PathResolution: "unresolved_cwd"}) {
		t.Fatal("state-changing unresolved event was dropped")
	}
	if !s.shouldRetainFile(model.FileDetail{Op: "unknown", Correlation: "incomplete"}) {
		t.Fatal("correlation uncertainty was dropped")
	}
	nonAgent := &session{meta: runs.Meta{CWD: "/workspace/project"}}
	if !nonAgent.shouldRetainFile(model.FileDetail{Op: "modify", Path: "/tmp/no-rule"}) {
		t.Fatal("ordinary run dropped state change")
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

func TestRenameResolvesBothDirFDPaths(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5}}
	base := t.TempDir()
	dir, err := os.Open(base) //nolint:gosec // Path returned by t.TempDir(), not user input.
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := dir.Close(); err != nil {
			t.Errorf("close directory: %v", err)
		}
	}()
	dirfd := int(dir.Fd()) //nolint:gosec // Successfully opened Linux file descriptors fit in int.
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
		runs.Meta{RunID: "r"},
		store, nil, nil, 1)
	detail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})
	for i := 0; i < 100; i++ {
		s.enqueue(collector.Event{Type: collector.EventTypeExec, PID: i + 1, Detail: detail})
	}
	if err := s.closeWithEnd(2, collector.DropCounts{File: 2}); err != nil {
		t.Fatal(err)
	}
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
	s.handleEvent(ev)
	if got := s.persistFailures.exec.Load(); got != 1 {
		t.Fatalf("exec persistence failures=%d", got)
	}
}

func TestOrdinaryFileRetentionAndCoverageRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(storage.OpenParams{RunID: "files", RunDir: dir, StartTS: 1, MetaJSON: `{}`})
	if err != nil {
		t.Fatal(err)
	}
	detector, err := detect.NewEngine("/home/test")
	if err != nil {
		t.Fatal(err)
	}
	s := newSession("s", os.Getuid(), os.Getgid(), dir, true, true, true, dir, dir,
		runs.Meta{RunID: "files", Version: 5}, store, detector, nil, 42)
	for _, op := range []string{"create", "create_or_open", "modify", "rename", "delete", "open"} {
		detail, _ := json.Marshal(model.FileDetail{Op: op, Path: "/ordinary/no-rule", Path2: "/ordinary/new", Correlation: "complete"})
		s.enqueue(collector.Event{Type: collector.EventTypeFile, Detail: detail})
	}
	// Rule-relevant opens are still retained.
	detail, _ := json.Marshal(model.FileDetail{Op: "open", Path: "/home/test/.aws/credentials"})
	s.enqueue(collector.Event{Type: collector.EventTypeFile, Detail: detail})
	detail, _ = json.Marshal(model.ProcessDetail{Kind: "fork", ParentTID: 10, ChildTID: 11, TaskStartKernelNS: 100, CgroupID: 42})
	s.enqueue(collector.Event{Type: collector.EventTypeProcess, Detail: detail})
	if err := s.closeWithEnd(2, collector.DropCounts{Exec: 1, File: 2, Net: 3, FileCorrelationFailures: 4}); err != nil {
		t.Fatal(err)
	}
	meta, err := runs.ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Coverage.Process.KnownLoss.CollectorForwardDropped != 1 || meta.Coverage.File.KnownLoss.Total() != 6 || meta.Coverage.Network.KnownLoss.Total() != 3 {
		t.Fatalf("coverage=%+v", meta.Coverage)
	}
	db, err := storage.OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	var persisted string
	if err := db.DB.QueryRow("SELECT meta_json FROM runs WHERE id = ?", "files").Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	var sqlMeta runs.Meta
	if err := json.Unmarshal([]byte(persisted), &sqlMeta); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(meta, sqlMeta) {
		t.Fatalf("metadata differs: sidecar=%+v sqlite=%+v", meta, sqlMeta)
	}
	files, err := db.Query(storage.QueryOptions{RunID: "files", Type: storage.TypeFile, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 6 {
		t.Fatalf("file events=%d, want 5 mutations + 1 rule-relevant open", len(files))
	}
	processes, err := db.Query(storage.QueryOptions{RunID: "files", Type: storage.TypeProcess})
	if err != nil || len(processes) != 1 {
		t.Fatalf("process query=%v, %v", processes, err)
	}
	events, err := storage.ReadJSONL(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if ev.Type == storage.TypeDetection && strings.Contains(string(ev.DataJSON), "create_or_open") {
			t.Fatal("ambiguous create emitted a create detection")
		}
	}
}

func TestFDPathIsNotRebasedAfterCWDChangeOrPIDReuse(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5, CWD: "/wrong"}}
	fd := 7
	for _, syscall := range []string{"write", "pwrite64", "writev", "ftruncate", "fchdir"} {
		path, resolution := s.resolveFilePath(model.FileDetail{TGID: os.Getpid(), FD: &fd, Syscall: syscall}, "original.txt", nil)
		if path != "original.txt" || resolution != "unresolved_fd_open_path" {
			t.Fatalf("%s: path=%q resolution=%q", syscall, path, resolution)
		}
	}
}

func TestAmbiguousCreationRetainedWithoutCreateDetection(t *testing.T) {
	detector, err := detect.NewEngineWithRules("/home/test", []detect.Rule{{
		ID: "create-test", Type: storage.TypeFile, Severity: "low", Message: "created",
		When: detect.WhenClause{File: &detect.FileWhen{OpIn: []string{"create"}, Prefix: "/ordinary"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	s := &session{detector: detector}
	for _, op := range []string{"create", "create_or_open"} {
		d := model.FileDetail{Op: op, Path: "/ordinary/new"}
		if !s.shouldRetainFile(d) {
			t.Fatalf("dropped %s", op)
		}
		raw, _ := json.Marshal(d)
		got := len(s.evaluateDetections(storage.TypeFile, raw))
		want := 0
		if op == "create" {
			want = 1
		}
		if got != want {
			t.Fatalf("%s detections=%d, want %d", op, got, want)
		}
	}
}

func TestRawPathsPreserveWhitespaceAndSymlinkTraversal(t *testing.T) {
	s := &session{meta: runs.Meta{Version: 5}}
	for _, path := range []string{"/tmp/a ", "/tmp/dir/link/../target"} {
		raw, _ := json.Marshal(model.FileDetail{Op: "modify", Path: path, Syscall: "truncate"})
		d, ok := s.normalizeFileDetail(collector.Event{Detail: raw})
		if !ok || d.Path != path || d.RawPath != path {
			t.Fatalf("path %q altered: %+v", path, d)
		}
	}
}
