package actionview

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func TestBuildNumbersOnlyCodexCommandExecutionsAndAttributesExactMembers(t *testing.T) {
	meta := completeMeta()
	events := []storage.Event{
		agentEvent(1, 10, model.AgentDetail{Provider: "codex", Kind: "turn_started"}),
		agentEvent(2, 11, model.AgentDetail{Provider: "codex", Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "in_progress"}),
		observedEvent(3, 12, storage.TypeExec, 20, model.ExecDetail{Filename: "/usr/bin/make", Argv: []string{"make", "test"}, TID: 20}),
		observedEvent(4, 13, storage.TypeFile, 20, model.FileDetail{PID: 20, TID: 20, Op: "modify", Path: "/repo/result.txt"}),
		observedEvent(5, 14, storage.TypeNet, 20, model.NetDetail{PID: 20, TID: 20, Op: "connect", Proto: "tcp", DstIP: "192.0.2.1", DstPort: 443}),
		agentEvent(6, 15, model.AgentDetail{Provider: "codex", Kind: "agent_message", Text: "done"}),
		agentEvent(7, 16, model.AgentDetail{Provider: "codex", Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "completed", Text: "ok\n"}),
		detectionEvent(8, 17, "E1", 3),
		detectionEvent(9, 18, "F1", 4),
		detectionEvent(10, 19, "N1", 5),
		// Same timestamp as episode evidence is deliberately insufficient.
		detectionEvent(11, 13, "RUN", 999),
	}

	view, err := Build(meta, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Actions) != 1 {
		t.Fatalf("actions=%d, want 1: %+v", len(view.Actions), view.Actions)
	}
	action := view.Actions[0]
	if action.Index != 1 || action.ItemID != "item_1" || action.RuntimeReport.Status != "completed" || action.RuntimeReport.Text != "ok\n" {
		t.Fatalf("action=%+v", action)
	}
	if action.Finding.Classification != residual.Matched || action.Episode == nil {
		t.Fatalf("action correlation=%+v", action)
	}
	if len(action.Detections) != 3 {
		t.Fatalf("episode detections=%+v", action.Detections)
	}
	if len(view.RunLevelDetections) != 1 || view.RunLevelDetections[0].RuleID != "RUN" {
		t.Fatalf("run-level detections=%+v", view.RunLevelDetections)
	}
	for _, detection := range action.Detections {
		if detection.RelatedEvent == nil || detection.RelatedEvent.Seq != detection.RelatedEventSeq {
			t.Fatalf("missing exact related evidence: %+v", detection)
		}
	}
}

func TestAmbiguousExactMembershipRemainsRunLevel(t *testing.T) {
	run := Run{
		Report: residual.Report{Episodes: []residual.ExecutionEpisode{
			{ExecMembers: []residual.ExecMember{{Seq: 3}}},
			{ExecMembers: []residual.ExecMember{{Seq: 3}}},
		}},
		Actions: []Action{{episodeIndex: 0}, {episodeIndex: 1}},
	}
	events := []storage.Event{detectionEvent(4, 20, "AMB", 3)}
	attributeDetections(&run, events)
	if len(run.RunLevelDetections) != 1 || len(run.Actions[0].Detections) != 0 || len(run.Actions[1].Detections) != 0 {
		t.Fatalf("ambiguous detection was attributed: %+v", run)
	}
}

func TestResolveActionByOrdinalAndItemID(t *testing.T) {
	run := Run{Actions: []Action{{Index: 1, ActionID: "item_a", ItemID: "item_a"}, {Index: 2, ActionID: "item_b", ItemID: "item_b"}}}
	for selector, want := range map[string]int{"1": 1, "2": 2, "item_b": 2} {
		action, err := run.ResolveAction(selector)
		if err != nil || action.Index != want {
			t.Fatalf("ResolveAction(%q)=(%+v,%v), want index %d", selector, action, err, want)
		}
	}
	if _, err := run.ResolveAction("3"); err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("missing useful ordinal error: %v", err)
	}
}

func TestBuildReportsPartialCoverageHonestly(t *testing.T) {
	meta := completeMeta()
	meta.Coverage.File.Capture = "partial"
	events := []storage.Event{
		agentEvent(1, 10, model.AgentDetail{Provider: "codex", Kind: "command_execution", ItemID: "i", Command: "echo hi", Status: "completed"}),
		observedEvent(2, 11, storage.TypeExec, 20, model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}, TID: 20}),
	}
	view, err := Build(meta, events)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.CoverageWarnings) == 0 || len(view.Actions[0].CoverageWarnings) == 0 {
		t.Fatalf("coverage warnings missing: %+v", view)
	}
}

func TestBuildCompletedCodexRunWithNoCommandsHasZeroActions(t *testing.T) {
	view, err := Build(completeMeta(), []storage.Event{
		agentEvent(1, 10, model.AgentDetail{Provider: "codex", Kind: "turn_started"}),
		agentEvent(2, 11, model.AgentDetail{Provider: "codex", Kind: "agent_message", Text: "no command needed"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Actions) != 0 {
		t.Fatalf("non-command items were numbered: %+v", view.Actions)
	}
}

func completeMeta() runs.Meta {
	return runs.Meta{
		RunID: "r", StartTS: 1, EndTS: 100, AgentProvider: "codex", CWD: "/repo",
		Coverage: runs.Coverage{
			Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
			Process: runs.KernelCoverage{Availability: "available", Capture: "complete"},
			File:    runs.KernelCoverage{Availability: "available", Capture: "complete"},
			Network: runs.KernelCoverage{Availability: "available", Capture: "complete"},
		},
	}
}

func agentEvent(seq, ts int64, detail model.AgentDetail) storage.Event {
	return storage.Event{RunID: "r", Seq: seq, TS: ts, Type: storage.TypeAgent, DataJSON: jsonBytes(detail)}
}

func observedEvent(seq, ts int64, typ storage.EventType, pid int, detail any) storage.Event {
	return storage.Event{RunID: "r", Seq: seq, TS: ts, Type: typ, PID: pid, DataJSON: jsonBytes(detail)}
}

func detectionEvent(seq, ts int64, rule string, related int64) storage.Event {
	detail := storage.Detection{RuleID: rule, Severity: "medium", Message: "detected " + rule, RelatedEventSeq: related}
	return storage.Event{RunID: "r", Seq: seq, TS: ts, Type: storage.TypeDetection, DataJSON: jsonBytes(detail)}
}

func jsonBytes(value any) json.RawMessage {
	data, _ := json.Marshal(value)
	return data
}
