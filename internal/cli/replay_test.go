package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/melonattacker/agentlogix/collector"
	"github.com/melonattacker/agentlogix/internal/logging"
)

func TestReplaySortsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	logA := filepath.Join(dir, "a.jsonl")
	logB := filepath.Join(dir, "b.jsonl")

	wa, _ := logging.NewJSONLWriter(logA)
	wb, _ := logging.NewJSONLWriter(logB)
	detail, _ := json.Marshal(map[string]any{"filename": "/bin/echo"})

	_ = wa.WriteEvent(collector.Event{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:03Z", PID: 3, Detail: detail})
	_ = wa.WriteEvent(collector.Event{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:01Z", PID: 1, Detail: detail})
	_ = wb.WriteEvent(collector.Event{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:02Z", PID: 2, Detail: detail})
	_ = wa.Close()
	_ = wb.Close()

	buf, restore := captureStdout(t)
	defer restore()

	if err := ReplayCommand(context.Background(), []string{"--log", dir}); err != nil {
		t.Fatalf("ReplayCommand: %v", err)
	}

	got := []collector.Event{}
	s := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	for s.Scan() {
		var ev collector.Event
		if err := json.Unmarshal(s.Bytes(), &ev); err != nil {
			t.Fatalf("unmarshal line: %v", err)
		}
		got = append(got, ev)
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	if got[0].PID != 1 || got[1].PID != 2 || got[2].PID != 3 {
		t.Fatalf("unexpected order: %+v", got)
	}
}
