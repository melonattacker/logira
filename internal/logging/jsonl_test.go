package logging

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/melonattacker/agentlogix/collector"
)

func TestWriteAndReadEventsSorted(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")

	w, err := NewJSONLWriter(logPath)
	if err != nil {
		t.Fatalf("NewJSONLWriter: %v", err)
	}

	detail, _ := json.Marshal(map[string]any{"filename": "/bin/echo"})
	events := []collector.Event{
		{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:03Z", PID: 3, Detail: detail},
		{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:01Z", PID: 1, Detail: detail},
		{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:02Z", PID: 2, Detail: detail},
	}
	for _, ev := range events {
		if err := w.WriteEvent(ev); err != nil {
			t.Fatalf("WriteEvent: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	files, err := CollectLogFiles(logPath)
	if err != nil {
		t.Fatalf("CollectLogFiles: %v", err)
	}
	got, err := ReadEvents(files)
	if err != nil {
		t.Fatalf("ReadEvents: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}
	if got[0].PID != 1 || got[1].PID != 2 || got[2].PID != 3 {
		t.Fatalf("unexpected order: %+v", got)
	}
}
