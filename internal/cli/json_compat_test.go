package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func TestAgentWorkflowJSONCompatibility(t *testing.T) {
	home := t.TempDir()
	t.Setenv("LOGIRA_HOME", home)
	runID := "20260829-130000-codex"
	runDir := filepath.Join(home, "runs", runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{
		RunID: runID, StartTS: 1, EndTS: 20, Command: "codex exec --json test", AgentProvider: "codex", CWD: "/repo",
		Coverage: runs.Coverage{
			Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
			Process: runs.KernelCoverage{Capture: "complete"}, File: runs.KernelCoverage{Capture: "complete"}, Network: runs.KernelCoverage{Capture: "complete"},
		},
	}
	if err := runs.WriteMeta(runDir, meta); err != nil {
		t.Fatal(err)
	}
	writer, err := storage.NewJSONLWriter(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	events := []storage.Event{
		{RunID: runID, Seq: 1, TS: 10, Type: storage.TypeAgent, Summary: "codex command echo hi", DataJSON: jsonRaw(model.AgentDetail{Provider: "codex", Kind: "command_execution", ItemID: "item_1", Command: "echo hi", Status: "completed", Text: "hi\n"})},
		{RunID: runID, Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, Summary: "exec echo hi", DataJSON: jsonRaw(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}, TID: 20})},
	}
	for _, event := range events {
		if err := writer.Append(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	viewJSON := captureCommandStdout(t, func() error {
		return ViewCommand(context.Background(), []string{"--json", runID})
	})
	assertJSONKeys(t, viewJSON, "meta", "timeline", "detections", "top_commands", "file_ops", "changed_files", "destinations")

	residualJSON := captureCommandStdout(t, func() error {
		return ResidualCommand(context.Background(), []string{runID, "--json"})
	})
	assertJSONKeys(t, residualJSON, "meta", "report")

	inspectJSON := captureCommandStdout(t, func() error {
		return InspectCommand(context.Background(), []string{runID, "action:1", "--json"})
	})
	assertJSONKeys(t, inspectJSON, "meta", "action")
	var inspectDoc struct {
		Action struct {
			Index    int    `json:"index"`
			ActionID string `json:"action_id"`
		} `json:"action"`
	}
	if err := json.Unmarshal([]byte(inspectJSON), &inspectDoc); err != nil {
		t.Fatal(err)
	}
	if inspectDoc.Action.Index != 1 || inspectDoc.Action.ActionID != "item_1" {
		t.Fatalf("unexpected inspect identity: %+v", inspectDoc.Action)
	}
}

func captureCommandStdout(t *testing.T, fn func() error) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = writer
	callErr := fn()
	_ = writer.Close()
	os.Stdout = old
	data, readErr := io.ReadAll(reader)
	_ = reader.Close()
	if callErr != nil {
		t.Fatal(callErr)
	}
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(data)
}

func assertJSONKeys(t *testing.T, document string, keys ...string) {
	t.Helper()
	var value map[string]json.RawMessage
	if err := json.Unmarshal([]byte(document), &value); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, document)
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			t.Fatalf("JSON missing key %q: %s", key, document)
		}
	}
}

func jsonRaw(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
