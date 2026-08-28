package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/runs"
)

func TestRenderExecForestDescendantReplacementAndIncompleteAncestry(t *testing.T) {
	episode := residual.ExecutionEpisode{
		AncestryComplete: false,
		ExecMembers: []residual.ExecMember{
			{Seq: 10, Filename: "/bin/bash", Role: residual.ExecRoleDirectMatch, PID: 20, Generation: 1},
			{Seq: 11, ParentExecSeq: 10, Filename: "/usr/bin/git", Argv: []string{"git", "status"}, Role: residual.ExecRoleExecReplacement, PID: 20, Generation: 2},
			{Seq: 12, ParentExecSeq: 11, Filename: "/bin/sh", Role: residual.ExecRoleDescendant, PID: 21, Generation: 1},
		},
	}
	detections := []actionview.Detection{{RelatedEventSeq: 11}}
	var out bytes.Buffer
	renderExecForest(&out, episode, detections, false)
	text := out.String()
	for _, want := range []string{"bash  [direct_match]", "└─ ⚠ git status  [exec_replacement]", "└─ sh  [descendant]", "? parent not observed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("tree missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "pid=") || strings.Contains(text, "seq=") {
		t.Fatalf("normal tree leaked raw identifiers:\n%s", text)
	}

	out.Reset()
	renderExecForest(&out, episode, detections, true)
	if !strings.Contains(out.String(), "seq=11 pid=20 gen=2 parent_seq=10") {
		t.Fatalf("verbose identifiers missing:\n%s", out.String())
	}
}

func TestInspectFileEffectsCompressesLargeSetsAndPrioritizesDetection(t *testing.T) {
	episode := residual.ExecutionEpisode{}
	for i := 0; i < 1000; i++ {
		episode.FileEffects = append(episode.FileEffects, residual.FileEffect{
			Seq: int64(i + 1), Op: "open", Path: "/repo/cache/data", Attribution: "task_instance_latest_exec_generation",
		})
	}
	episode.FileEffects = append(episode.FileEffects,
		residual.FileEffect{Seq: 2001, Op: "modify", Path: "/outside/detected", Attribution: "task_instance_latest_exec_generation"},
		residual.FileEffect{Seq: 2002, Op: "create", Path: "/repo/new.txt", Attribution: "task_instance_latest_exec_generation"},
	)
	var out bytes.Buffer
	renderInspectFileEffects(&out, runs.Meta{CWD: "/repo"}, episode, []actionview.Detection{{RelatedEventSeq: 2001}}, 2, false)
	text := out.String()
	if strings.Index(text, "/outside/detected") > strings.Index(text, "new.txt") || !strings.Contains(text, "⚠ MODIFY") {
		t.Fatalf("detection-linked effect was not prioritized:\n%s", text)
	}
	if !strings.Contains(text, "1000") || !strings.Contains(text, "omitted") {
		t.Fatalf("large effect set was not summarized:\n%s", text)
	}
	if strings.Count(text, "cache/data") > 1 {
		t.Fatalf("repeated effects were dumped:\n%s", text)
	}
}

func TestRenderAgentRunViewKeepsMatchedClassificationWithDetection(t *testing.T) {
	view := actionview.Run{
		Meta: runs.Meta{
			RunID: "r", Command: "codex exec --json inspect", StartTS: 1, EndTS: 2,
			Coverage: runs.Coverage{
				Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
				Process: runs.KernelCoverage{Capture: "complete"}, File: runs.KernelCoverage{Capture: "complete"}, Network: runs.KernelCoverage{Capture: "partial"},
			},
		},
		Report: residual.Report{Counts: map[residual.Classification]int{residual.Matched: 2, residual.ReportedNotObserved: 1}},
		Actions: []actionview.Action{
			{Index: 1, RuntimeReport: actionview.RuntimeReport{Command: "pwd"}, Finding: residual.Finding{Classification: residual.Matched}, Episode: &residual.ExecutionEpisode{Summary: residual.EpisodeSummary{Execs: 1, Processes: 1}}},
			{Index: 2, RuntimeReport: actionview.RuntimeReport{Command: "git status"}, Finding: residual.Finding{Classification: residual.Matched}, Episode: &residual.ExecutionEpisode{Summary: residual.EpisodeSummary{Execs: 2, Processes: 2, Files: 4}}, Detections: []actionview.Detection{{Severity: "medium", RuleID: "R12", Message: "workspace executable"}}},
			{Index: 3, RuntimeReport: actionview.RuntimeReport{Command: "curl https://example.com"}, Finding: residual.Finding{Classification: residual.ReportedNotObserved}},
		},
	}
	var out bytes.Buffer
	renderAgentRunView(&out, view, 10, cliui.TSRel, cliui.Colorizer{})
	text := out.String()
	for _, want := range []string{"Agent actions  3", "2 matched · 1 mismatch", "#1  ✓ MATCHED", "#2  ⚠ MATCHED", "#3  ✕ REPORTED_NOT_OBSERVED", "detections 1", "network partial", "inspect r action:1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("agent view missing %q:\n%s", want, text)
		}
	}
}

func TestInspectNetworkEffectsGroupsDestinations(t *testing.T) {
	episode := residual.ExecutionEpisode{}
	for i := 0; i < 100; i++ {
		episode.NetworkEffects = append(episode.NetworkEffects, residual.NetworkEffect{
			Seq: int64(i + 1), Op: "send", Proto: "tcp", DstIP: "192.0.2.1", DstPort: 443, Bytes: 10,
		})
	}
	episode.NetworkEffects = append(episode.NetworkEffects, residual.NetworkEffect{
		Seq: 200, Op: "connect", Proto: "tcp", DstIP: "198.51.100.2", DstPort: 8443,
	})
	var out bytes.Buffer
	renderInspectNetworkEffects(&out, episode, []actionview.Detection{{RelatedEventSeq: 200}}, 1, false)
	text := out.String()
	if !strings.Contains(text, "⚠ connect") || !strings.Contains(text, "198.51.100.2:8443") || !strings.Contains(text, "omitted") {
		t.Fatalf("network destinations were not prioritized and compressed:\n%s", text)
	}
}

func TestInspectNonAgentRunReturnsUsefulError(t *testing.T) {
	err := validateActionInspectionRun(runs.Meta{RunID: "r", EndTS: 2}, "r")
	if err == nil || !strings.Contains(err.Error(), "no supported agent runtime telemetry") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTruncateRuntimeOutput(t *testing.T) {
	input := strings.Repeat("line\n", 100)
	output, truncated := truncateRuntimeOutput(input, false)
	if !truncated || strings.Count(output, "\n") >= 100 {
		t.Fatalf("output was not truncated: lines=%d truncated=%v", strings.Count(output, "\n"), truncated)
	}
	full, truncated := truncateRuntimeOutput(input, true)
	if truncated || full != input {
		t.Fatal("verbose output should expose the complete stored value")
	}
}
