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

func TestAgentSequenceIsNotDetectionMembership(t *testing.T) {
	run := Run{
		Report:  residual.Report{Episodes: []residual.ExecutionEpisode{{AgentSeq: 7, ExecMembers: []residual.ExecMember{{Seq: 8}}}}},
		Actions: []Action{{episodeIndex: 0}},
	}
	attributeDetections(&run, []storage.Event{detectionEvent(9, 20, "AGENT", 7)})
	if len(run.RunLevelDetections) != 1 || len(run.Actions[0].Detections) != 0 {
		t.Fatalf("agent runtime sequence was used as episode membership: %+v", run)
	}
}

func TestProcessForkAndExitSequencesAreExactDetectionMembership(t *testing.T) {
	run := Run{
		Report: residual.Report{Episodes: []residual.ExecutionEpisode{{
			ProcessMembers: []residual.ProcessMember{{ForkSeq: 30, ExitSeq: 31}},
		}}},
		Actions: []Action{{episodeIndex: 0}},
	}
	attributeDetections(&run, []storage.Event{
		detectionEvent(40, 20, "FORK", 30),
		detectionEvent(41, 21, "EXIT", 31),
		detectionEvent(42, 22, "OTHER", 32),
	})
	if len(run.Actions[0].Detections) != 2 || len(run.RunLevelDetections) != 1 || run.RunLevelDetections[0].RuleID != "OTHER" {
		t.Fatalf("process sequence attribution=%+v run-level=%+v", run.Actions[0].Detections, run.RunLevelDetections)
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

func TestCoverageWarningsTreatNeutralStatesAsNeutral(t *testing.T) {
	meta := completeMeta()
	meta.Coverage.Network.Capture = "not_applicable"
	meta.Coverage.File.Capture = ""
	meta.Coverage.File.Availability = "unavailable"
	if warnings := CoverageWarnings(meta); len(warnings) != 0 {
		t.Fatalf("neutral capture states warned: %v", warnings)
	}
	meta.Coverage.Process.KnownLoss.SessionQueueDropped = 2
	if warnings := CoverageWarnings(meta); len(warnings) != 1 || !strings.Contains(warnings[0], "2 known lost") {
		t.Fatalf("known loss warning=%v", warnings)
	}
}

func TestEpisodeWarningsFiltersOnlyNeutralCaptureBoilerplate(t *testing.T) {
	episode := residual.ExecutionEpisode{
		ProcessCapture: "partial", FileCapture: "unavailable", NetworkCapture: "not_applicable",
		AttributionIssues: []string{
			"process capture is not complete; episode membership may be incomplete",
			"file capture is not complete; attributed file effects may be incomplete",
			"network capture is not complete; attributed network effects may be incomplete",
			"direct match parent exec was not observed",
		},
	}
	warnings := EpisodeWarnings(episode)
	if len(warnings) != 2 || !strings.Contains(warnings[0], "process capture") || !strings.Contains(warnings[1], "parent exec") {
		t.Fatalf("filtered warnings=%v", warnings)
	}
	if len(episode.AttributionIssues) != 4 {
		t.Fatalf("episode was mutated: %v", episode.AttributionIssues)
	}
}

func TestGroupDetectionsUsesExactIdentityAndStablePriority(t *testing.T) {
	groups := GroupDetections([]Detection{
		{Severity: " medium ", RuleID: "E2", Message: "same"},
		{Severity: "MEDIUM", RuleID: "E2", Message: "same"},
		{Severity: "high", RuleID: "E1", Message: "urgent"},
		{Severity: "medium", RuleID: "E2", Message: "different"},
	})
	if len(groups) != 3 || groups[0].RuleID != "E1" || groups[1].Count != 2 || groups[1].Message != "same" {
		t.Fatalf("groups=%+v", groups)
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
