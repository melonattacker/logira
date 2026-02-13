package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/melonattacker/agentlogix/collector"
	"github.com/melonattacker/agentlogix/internal/logging"
)

func TestSummarizeJSON(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.jsonl")

	w, err := logging.NewJSONLWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}

	mustWrite := func(ev collector.Event) {
		t.Helper()
		if err := w.WriteEvent(ev); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	execDetail, _ := json.Marshal(map[string]any{"filename": "/usr/bin/git", "argv": []string{"git", "status"}})
	fileDetail, _ := json.Marshal(map[string]any{"op": "modify", "path": "/repo/a.txt"})
	netConn, _ := json.Marshal(map[string]any{"op": "connect", "proto": "tcp", "dst_ip": "1.2.3.4", "dst_port": 443})
	netSend, _ := json.Marshal(map[string]any{"op": "send", "proto": "tcp", "dst_ip": "1.2.3.4", "dst_port": 443, "bytes": 10})
	netRecv, _ := json.Marshal(map[string]any{"op": "recv", "proto": "tcp", "dst_ip": "1.2.3.4", "dst_port": 443, "bytes": 20})

	mustWrite(collector.Event{Type: collector.EventTypeExec, Timestamp: "2026-01-01T00:00:01Z", PID: 1, Detail: execDetail})
	mustWrite(collector.Event{Type: collector.EventTypeFile, Timestamp: "2026-01-01T00:00:02Z", PID: 1, Detail: fileDetail})
	mustWrite(collector.Event{Type: collector.EventTypeNet, Timestamp: "2026-01-01T00:00:03Z", PID: 1, Detail: netConn})
	mustWrite(collector.Event{Type: collector.EventTypeNet, Timestamp: "2026-01-01T00:00:04Z", PID: 1, Detail: netSend})
	mustWrite(collector.Event{Type: collector.EventTypeNet, Timestamp: "2026-01-01T00:00:05Z", PID: 1, Detail: netRecv})

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	buf, restore := captureStdout(t)
	defer restore()

	if err := SummarizeCommand(context.Background(), []string{"--log", logPath, "--json"}); err != nil {
		t.Fatalf("SummarizeCommand: %v", err)
	}

	var out summaryOut
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("decode summary: %v\noutput=%s", err, buf.String())
	}

	if len(out.ExecCommands) == 0 || out.ExecCommands[0].Count != 1 {
		t.Fatalf("unexpected exec summary: %+v", out.ExecCommands)
	}
	if len(out.FileOps) == 0 || out.FileOps[0].Key != "modify" || out.FileOps[0].Count != 1 {
		t.Fatalf("unexpected file summary: %+v", out.FileOps)
	}
	if len(out.Network) == 0 {
		t.Fatalf("missing network summary")
	}
	if out.Network[0].Conns != 1 || out.Network[0].Sent != 10 || out.Network[0].Recv != 20 {
		t.Fatalf("unexpected network summary: %+v", out.Network[0])
	}
}

func captureStdout(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	buf := &bytes.Buffer{}
	done := make(chan struct{})
	go func() {
		_, _ = buf.ReadFrom(r)
		close(done)
	}()
	return buf, func() {
		_ = w.Close()
		os.Stdout = old
		<-done
		_ = r.Close()
	}
}
