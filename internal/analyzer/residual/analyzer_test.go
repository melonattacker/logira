package residual

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func event(seq, ts int64, typ storage.EventType, data any) storage.Event {
	b, _ := json.Marshal(data)
	return storage.Event{RunID: "r", Seq: seq, TS: ts, Type: typ, DataJSON: b}
}

func completeMeta() runs.Meta {
	return runs.Meta{RunID: "r", CommandArgv: []string{"codex", "exec", "--json"}, Coverage: runs.Coverage{
		Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
		Process: runs.KernelCoverage{Availability: "available", Capture: "complete"},
		File:    runs.KernelCoverage{Availability: "available", Capture: "complete"},
		Network: runs.KernelCoverage{Availability: "available", Capture: "complete"},
	}}
}

func TestMatchedAndDescendant(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "bash -lc echo hi", Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec bash", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-lc", "echo hi"}})},
		{RunID: "r", Seq: 3, TS: 12, Type: storage.TypeExec, PID: 11, PPID: 10, Summary: "exec echo", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})},
		event(4, 13, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "bash -lc echo hi", Status: "completed"}),
	}
	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Counts[ObservedNotReported] != 0 {
		t.Fatalf("report=%+v", r)
	}
}

func TestKnownExecLossMakesMissingUnobservable(t *testing.T) {
	m := completeMeta()
	m.Coverage.Process.Capture = "partial"
	m.Coverage.Process.KnownLoss.SessionQueueDropped = 2
	r := Analyze(m, []storage.Event{event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "git status", Status: "completed"})})
	if r.Counts[Unobservable] != 1 || r.Counts[ReportedNotObserved] != 0 {
		t.Fatalf("report=%+v", r)
	}
}

func TestDeclinedOnlyStructuredBlocked(t *testing.T) {
	m := completeMeta()
	declined := Analyze(m, []storage.Event{event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", Command: "git status", Status: "declined"})})
	failed := Analyze(m, []storage.Event{event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", Command: "git status", Status: "failed"})})
	if declined.Counts[Blocked] != 1 || failed.Counts[Blocked] != 0 || failed.Counts[ReportedNotObserved] != 1 {
		t.Fatalf("declined=%+v failed=%+v", declined, failed)
	}
}

func TestDeclinedWithKernelEvidenceIsMatched(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "git status", Status: "declined"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec git status", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"git", "status"}})},
	}
	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Counts[Blocked] != 0 || !strings.Contains(r.Findings[0].Reason, "conflicts") {
		t.Fatalf("report=%+v", r)
	}
}

func TestUnmatchedKernelActivityRequiresCompleteAncestryAndAgentCoverage(t *testing.T) {
	m := completeMeta()
	launcher := storage.Event{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})}
	unreported := storage.Event{RunID: "r", Seq: 2, TS: 2, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec curl", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/curl"})}
	r := Analyze(m, []storage.Event{launcher, unreported})
	if r.Counts[ObservedNotReported] != 1 {
		t.Fatalf("report=%+v", r)
	}

	unreported.PPID = 999
	r = Analyze(m, []storage.Event{launcher, unreported})
	if r.Counts[Unobservable] != 1 || r.Counts[ObservedNotReported] != 0 {
		t.Fatalf("incomplete ancestry report=%+v", r)
	}

	unreported.PPID = 10
	m.Coverage.Agent.Interpretation = "partial"
	r = Analyze(m, []storage.Event{launcher, unreported})
	if r.Counts[Unobservable] != 1 || r.Counts[ObservedNotReported] != 0 {
		t.Fatalf("partial interpretation report=%+v", r)
	}
}

func TestMatchSurvivesPartialProcessCapture(t *testing.T) {
	m := completeMeta()
	m.Coverage.Process.Capture = "partial"
	m.Coverage.Process.KnownLoss.CollectorForwardDropped = 1
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", Command: "/bin/echo hi", Status: "completed"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec echo hi", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})},
	}
	r := Analyze(m, events)
	if r.Counts[Matched] != 1 {
		t.Fatalf("report=%+v", r)
	}
}

func TestReportedShellWrapperMatchesObservedPayload(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", Command: `/bin/bash -lc "git status"`, Status: "completed"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec git status", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"git", "status"}})},
	}
	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Findings[0].Confidence != "high" {
		t.Fatalf("report=%+v", r)
	}
}

func TestSamePIDExecReplacementDoesNotInheritLauncherExclusion(t *testing.T) {
	m := completeMeta()
	command := `/bin/bash -c "printf \"ACTION_RESIDUAL_SMOKE\n\""`
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 42, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex", Argv: []string{"codex", "exec", "--json"}})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		{RunID: "r", Seq: 3, TS: 8, Type: storage.TypeExec, PID: 42, PPID: 1, Summary: "exec sandbox wrapper", DataJSON: mustJSON(model.ExecDetail{Filename: "/opt/codex", Argv: []string{"codex-linux-sandbox", "--", "/bin/bash", "-c", `printf "ACTION_RESIDUAL_SMOKE\n"`}})},
		{RunID: "r", Seq: 4, TS: 9, Type: storage.TypeExec, PID: 42, PPID: 1, Summary: "exec bash", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"/bin/bash", "-c", `printf "ACTION_RESIDUAL_SMOKE\n"`}})},
		event(5, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Counts[ReportedNotObserved] != 0 {
		t.Fatalf("report=%+v", r)
	}
	if got := r.Findings[0]; got.ExecSeq != 4 || got.Confidence != "high" {
		t.Fatalf("match=%+v", got)
	}
}

func TestSandboxWrapperAndDescendantsFormOneExecutionEpisode(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex", Argv: []string{"codex", "exec", "--json"}})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		{RunID: "r", Seq: 3, TS: 8, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec bwrap", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/bwrap", Argv: []string{"bwrap", "--", "/bin/bash", "-c", "echo hi"}})},
		{RunID: "r", Seq: 4, TS: 9, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec bash", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "echo hi"}})},
		{RunID: "r", Seq: 5, TS: 10, Type: storage.TypeExec, PID: 21, PPID: 20, Summary: "exec echo", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})},
		event(6, 11, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "/bin/bash -c \"echo hi\"", Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || len(r.Findings) != 1 {
		t.Fatalf("report=%+v", r)
	}
	if !strings.Contains(r.Findings[0].Reason, "3 exec observation") {
		t.Fatalf("episode not attributed: %+v", r.Findings[0])
	}
}

func TestUnmatchedProcessSubtreeProducesOneFinding(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		{RunID: "r", Seq: 2, TS: 2, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec custom", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/custom"})},
		{RunID: "r", Seq: 3, TS: 3, Type: storage.TypeExec, PID: 21, PPID: 20, Summary: "exec child", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/child"})},
		{RunID: "r", Seq: 4, TS: 4, Type: storage.TypeExec, PID: 21, PPID: 20, Summary: "exec child replacement", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/child2"})},
	}

	r := Analyze(m, events)
	if r.Counts[ObservedNotReported] != 1 || len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Reason, "3 exec observation") {
		t.Fatalf("report=%+v", r)
	}
}

func TestIncompleteAncestryNoiseIsAggregated(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		{RunID: "r", Seq: 2, TS: 2, Type: storage.TypeExec, PID: 20, PPID: 900, Summary: "exec one", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/one"})},
		{RunID: "r", Seq: 3, TS: 3, Type: storage.TypeExec, PID: 30, PPID: 901, Summary: "exec two", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/two"})},
		{RunID: "r", Seq: 4, TS: 4, Type: storage.TypeExec, PID: 40, PPID: 902, Summary: "exec three", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/three"})},
	}

	r := Analyze(m, events)
	if r.Counts[Unobservable] != 1 || len(r.Findings) != 1 || !strings.Contains(r.Findings[0].Reason, "3 unmatched exec observation") {
		t.Fatalf("report=%+v", r)
	}
}

func TestLearnedStartupInfrastructureDoesNotProduceResidualFlood(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		{RunID: "r", Seq: 3, TS: 3, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec runtime probe", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/runtime-probe", Argv: []string{"runtime-probe", "--metadata"}})},
		{RunID: "r", Seq: 4, TS: 8, Type: storage.TypeExec, PID: 30, PPID: 10, Summary: "exec bash", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "echo hi"}})},
		event(5, 9, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "i", Command: "bash -c \"echo hi\"", Status: "completed"}),
		{RunID: "r", Seq: 6, TS: 10, Type: storage.TypeExec, PID: 31, PPID: 10, Summary: "exec repeated runtime probe", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/runtime-probe", Argv: []string{"runtime-probe", "--metadata"}})},
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || len(r.Findings) != 1 {
		t.Fatalf("report=%+v", r)
	}
}

func TestNoCommandTurnTreatsLifecycleActivityAsInfrastructure(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		{RunID: "r", Seq: 3, TS: 3, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec runtime probe", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/runtime-probe"})},
		{RunID: "r", Seq: 4, TS: 4, Type: storage.TypeExec, PID: 21, PPID: 999, Summary: "exec setup with incomplete ancestry", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/setup-helper"})},
		event(5, 5, storage.TypeAgent, model.AgentDetail{Kind: "agent_message", Text: "NO_COMMAND_OK"}),
		event(6, 6, storage.TypeAgent, model.AgentDetail{Kind: "turn_completed"}),
	}

	r := Analyze(m, events)
	if len(r.Findings) != 0 {
		t.Fatalf("no-command harness activity produced residuals: %+v", r)
	}
}

func TestRepeatedIdenticalCommandsCorrelateByLifecycleOrder(t *testing.T) {
	m := completeMeta()
	command := `/bin/bash -c "printf REPEAT"`
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		event(2, 1_000_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "in_progress"}),
		{RunID: "r", Seq: 3, TS: 1_010_000_000, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "first repeat", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "printf REPEAT"}})},
		event(4, 1_020_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "completed"}),
		event(5, 2_000_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_2", Command: command, Status: "in_progress"}),
		{RunID: "r", Seq: 6, TS: 2_010_000_000, Type: storage.TypeExec, PID: 21, PPID: 10, Summary: "second repeat", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "printf REPEAT"}})},
		event(7, 2_020_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_2", Command: command, Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 2 || len(r.Findings) != 2 {
		t.Fatalf("report=%+v", r)
	}
	if r.Findings[0].ExecSeq != 3 || r.Findings[1].ExecSeq != 6 {
		t.Fatalf("repeated commands not paired in lifecycle order: %+v", r.Findings)
	}
}

func TestTruncatedObservedArgvMatchesWithLowConfidence(t *testing.T) {
	m := completeMeta()
	payload := strings.Repeat("A", 600)
	command := `/bin/bash -c "/usr/bin/printf %s ` + payload + `"`
	truncated := `/usr/bin/printf %s ` + payload[:200]
	events := []storage.Event{
		event(1, 1_000_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 1_010_000_000, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "truncated shell argv", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", truncated}})},
		event(3, 1_020_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Findings[0].Confidence != "low" {
		t.Fatalf("truncated argv must not claim strong identity: %+v", r)
	}
}

func TestEqualScoreAndLifecycleDistanceRemainsAmbiguous(t *testing.T) {
	m := completeMeta()
	command := "bash -c true"
	events := []storage.Event{
		event(1, 1_000_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 1_010_000_000, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "candidate one", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "true"}})},
		{RunID: "r", Seq: 3, TS: 1_010_000_000, Type: storage.TypeExec, PID: 21, PPID: 10, Summary: "candidate two", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "true"}})},
		event(4, 1_020_000_000, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[ReportedNotObserved] != 1 || r.Counts[Matched] != 0 || !strings.Contains(r.Findings[0].Reason, "multiple equally plausible") {
		t.Fatalf("ambiguous candidates were forced: %+v", r)
	}
}

func mustJSON(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
