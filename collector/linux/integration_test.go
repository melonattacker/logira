//go:build linux && integration

package linuxcollector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	collector "github.com/melonattacker/logira/collector/common"
)

func TestCollectorIntegrationSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for eBPF/fanotify integration test")
	}

	tmp := t.TempDir()
	outFile := filepath.Join(tmp, "x.txt")

	cfg := collector.Config{
		EnableExec:   true,
		EnableFile:   true,
		EnableNet:    false,
		WatchPaths:   []string{tmp},
		ArgvMax:      20,
		ArgvMaxBytes: 256,
		HashMaxBytes: 1024 * 1024,
	}

	c := NewCollector(cfg)
	ctx := context.Background()
	if err := c.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}

	events := make(chan collector.Event, 4096)
	if err := c.Start(ctx, events); err != nil {
		t.Fatalf("start: %v", err)
	}

	cmd := exec.Command("bash", "-lc", "echo hi > \""+outFile+"\"")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c.SetTargetPID(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(750 * time.Millisecond)
	_ = c.Stop(context.Background())
	close(events)

	count := 0
	for range events {
		count++
	}
	if count == 0 {
		t.Fatalf("expected at least one event")
	}
}
