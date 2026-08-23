//go:build linux && integration

package filetrace

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/melonattacker/logira/internal/model"
)

func TestFileLifecyclePipeline(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for eBPF integration test")
	}
	tracer := NewTracer()
	ctx := context.Background()
	events, err := tracer.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	var mu sync.Mutex
	var got []model.FileDetail
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range events {
			var d model.FileDetail
			if json.Unmarshal(ev.Detail, &d) == nil && (filepath.Dir(d.Path) == tmp || filepath.Dir(d.Path2) == tmp) {
				mu.Lock()
				got = append(got, d)
				mu.Unlock()
			}
		}
	}()

	created := filepath.Join(tmp, "created.txt")
	fd, err := unix.Openat2(unix.AT_FDCWD, created, &unix.OpenHow{Flags: unix.O_CREAT | unix.O_EXCL | unix.O_WRONLY, Mode: 0o600})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, []byte("one")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	createOrOpen := filepath.Join(tmp, "create-or-open.txt")
	fd, err = unix.Open(createOrOpen, unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)

	fd, err = unix.Open(created, unix.O_WRONLY|unix.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Write(fd, []byte("two")); err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)

	renamed := filepath.Join(tmp, "renamed.txt")
	if err := os.Rename(created, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(renamed, 1); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}
	pythonPath := filepath.Join(tmp, "python.txt")
	if python, err := exec.LookPath("python3"); err == nil {
		if err := exec.Command(python, "-c", "from pathlib import Path; Path("+strconv.Quote(pythonPath)+").write_text('python')").Run(); err != nil {
			t.Fatal(err)
		}
	}
	shellPath := filepath.Join(tmp, "shell-redirection.txt")
	if bash, err := exec.LookPath("bash"); err == nil {
		command := "printf shell > " + strconv.Quote(shellPath) + "; printf append >> " + strconv.Quote(shellPath)
		if err := exec.Command(bash, "-c", command).Run(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := unix.Open(filepath.Join(tmp, "missing", "failed.txt"), unix.O_CREAT|unix.O_WRONLY, 0o600); err == nil {
		t.Fatal("expected failed open")
	}

	time.Sleep(300 * time.Millisecond)
	stats := tracer.Stats()
	pending := tracer.coll.Maps["pending_file_ops"]
	if pending == nil {
		t.Fatal("pending_file_ops map missing")
	}
	pendingKey := uint32(0xfffffff0)
	pendingValue := rawPendingFileOp{CgroupID: 0xfeed, TID: pendingKey, Kind: 1, Syscall: 1}
	if err := pending.Update(&pendingKey, &pendingValue, 0); err != nil {
		t.Fatal(err)
	}
	if got := tracer.FinalizeCgroup(0xfeed); got != 1 {
		t.Fatalf("missing-exit cleanup=%d, want 1", got)
	}
	if got := tracer.FinalizeCgroup(0xfeed); got != 0 {
		t.Fatalf("pending state was not deleted: %d", got)
	}
	if err := tracer.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-done

	mu.Lock()
	defer mu.Unlock()
	for _, want := range []string{"create", "create_or_open", "modify", "rename", "delete"} {
		if !hasFileOp(got, want) {
			t.Fatalf("missing op %q; events=%+v", want, got)
		}
	}
	for _, want := range []struct {
		name    string
		op      string
		syscall string
		path    string
	}{
		{name: "create", op: "create", syscall: "openat2", path: created},
		{name: "python write", op: "modify", syscall: "write", path: pythonPath},
		{name: "truncate", op: "modify", syscall: "truncate", path: renamed},
		{name: "delete", op: "delete", syscall: "unlinkat", path: renamed},
	} {
		if !hasFileOpSyscallPath(got, want.op, want.syscall, want.path) {
			t.Fatalf("missing %s event op=%q syscall=%q path=%q; events=%+v", want.name, want.op, want.syscall, want.path, got)
		}
	}
	if !hasFileOpSyscallPathFlags(got, "modify", "write", created, unix.O_APPEND) {
		t.Fatalf("missing append event op=modify syscall=write path=%q flags&=%d; events=%+v", created, unix.O_APPEND, got)
	}
	if !hasRename(got, created, renamed) {
		t.Fatalf("missing rename event %q -> %q; events=%+v", created, renamed, got)
	}
	if count := countFileOpPath(got, "modify", shellPath); count < 2 {
		t.Fatalf("shell redirection writes lost dup provenance: got %d modify events; events=%+v", count, got)
	}
	for _, event := range got {
		if strings.Contains(event.Path, "failed.txt") {
			t.Fatalf("failed syscall fabricated an effect: %+v", event)
		}
	}
	if stats.BPFEmitted == 0 || stats.RingSamples == 0 || stats.Decoded == 0 || stats.DecodeFailures != 0 {
		t.Fatalf("pipeline counters=%+v", stats)
	}
}

func hasFileOpPath(events []model.FileDetail, op, path string) bool {
	return countFileOpPath(events, op, path) > 0
}

func hasFileOpSyscallPath(events []model.FileDetail, op, syscall, path string) bool {
	for _, event := range events {
		if event.Op == op && event.Syscall == syscall && event.Path == path {
			return true
		}
	}
	return false
}

func hasFileOpSyscallPathFlags(events []model.FileDetail, op, syscall, path string, requiredFlags int) bool {
	for _, event := range events {
		if event.Op == op && event.Syscall == syscall && event.Path == path && int(event.Flags)&requiredFlags == requiredFlags {
			return true
		}
	}
	return false
}

func hasRename(events []model.FileDetail, oldPath, newPath string) bool {
	for _, event := range events {
		if event.Op == "rename" && event.Path == oldPath && event.Path2 == newPath {
			return true
		}
	}
	return false
}

func countFileOpPath(events []model.FileDetail, op, path string) int {
	count := 0
	for _, event := range events {
		if event.Op == op && event.Path == path {
			count++
		}
	}
	return count
}

func hasFileOp(events []model.FileDetail, op string) bool {
	for _, event := range events {
		if event.Op == op {
			return true
		}
	}
	return false
}
