package cli

import (
	"bytes"
	"fmt"
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
	renderExecForest(&out, "/repo", "codex", episode, detections, false)
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
	renderExecForest(&out, "/repo", "codex", episode, detections, true)
	if !strings.Contains(out.String(), "seq=11 pid=20 gen=2 parent_seq=10") {
		t.Fatalf("verbose identifiers missing:\n%s", out.String())
	}
}

func TestRenderExecForestCollapsesOnlyExactCodexInfrastructure(t *testing.T) {
	episode := residual.ExecutionEpisode{AncestryComplete: true, ExecMembers: []residual.ExecMember{
		{Seq: 1, Filename: "/home/u/.codex/tmp/codex-linux-sandbox", Argv: []string{"codex-linux-sandbox"}, Role: residual.ExecRoleWrapper},
		{Seq: 2, ParentExecSeq: 1, Filename: "/usr/bin/bwrap", Argv: []string{"bwrap", "--help"}, Role: residual.ExecRoleWrapper},
		{Seq: 3, ParentExecSeq: 2, Filename: "/usr/bin/true", Argv: []string{"true"}, Role: residual.ExecRoleWrapper},
		{Seq: 4, ParentExecSeq: 2, Filename: "/opt/codex/vendor/codex", Argv: []string{"codex-linux-sandbox", "--apply-seccomp-then-exec"}, Role: residual.ExecRoleWrapper},
		{Seq: 5, ParentExecSeq: 4, Filename: "/bin/bash", Argv: []string{"bash", "-c", "pwd"}, Role: residual.ExecRoleDirectMatch},
		{Seq: 6, ParentExecSeq: 5, Filename: "/repo/tool", Argv: []string{"tool"}, Role: residual.ExecRoleDescendant},
	}}
	var out bytes.Buffer
	renderExecForest(&out, "/repo", "codex", episode, nil, false)
	text := out.String()
	for _, want := range []string{"4 exec observation(s) collapsed", "bash -c pwd  [direct_match]", "tool (tool)  [descendant]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("normal tree missing %q:\n%s", want, text)
		}
	}
	for _, hidden := range []string{"bwrap", "true  [", "codex-linux-sandbox"} {
		if strings.Contains(text, hidden) {
			t.Fatalf("normal tree retained infrastructure %q:\n%s", hidden, text)
		}
	}

	out.Reset()
	renderExecForest(&out, "/repo", "codex", episode, nil, true)
	for _, want := range []string{"codex-linux-sandbox", "bwrap", "true", "seq=4", "exe=/opt/codex/vendor/codex"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("verbose tree missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "collapsed") {
		t.Fatalf("verbose tree was collapsed:\n%s", out.String())
	}

	out.Reset()
	renderExecForest(&out, "/repo", "codex", episode, []actionview.Detection{{RelatedEventSeq: 2}}, false)
	if !strings.Contains(out.String(), "⚠ bwrap") {
		t.Fatalf("detected infrastructure node was collapsed:\n%s", out.String())
	}
}

func TestRenderExecForestGroupsOnlyEligibleSiblingLeaves(t *testing.T) {
	members := []residual.ExecMember{
		{Seq: 1, Filename: "/bin/bash", Role: residual.ExecRoleDirectMatch},
		{Seq: 2, ParentExecSeq: 1, Filename: "/usr/bin/go", Role: residual.ExecRoleExecReplacement},
		{Seq: 3, ParentExecSeq: 2, Filename: "/usr/bin/parent-a", Role: residual.ExecRoleDescendant},
		{Seq: 4, ParentExecSeq: 2, Filename: "/usr/bin/parent-b", Role: residual.ExecRoleDescendant},
	}
	seq := int64(5)
	for _, parent := range []int64{3, 4} {
		for i := 0; i < 3; i++ {
			members = append(members, residual.ExecMember{Seq: seq, ParentExecSeq: parent, Filename: "/usr/lib/go/pkg/tool/compile", Role: residual.ExecRoleDescendant})
			seq++
		}
	}
	// Structurally significant and heterogeneous leaves take the tree over the
	// grouping threshold and must remain individual.
	for i := 0; i < 15; i++ {
		members = append(members, residual.ExecMember{Seq: seq, ParentExecSeq: 2, Filename: fmt.Sprintf("/tmp/tool-%d", i), Role: residual.ExecRoleDescendant})
		seq++
	}
	members = append(members,
		residual.ExecMember{Seq: seq, ParentExecSeq: 2, Filename: "/usr/lib/go/pkg/tool/compile", Role: residual.ExecRoleExecReplacement},
		residual.ExecMember{Seq: seq + 1, ParentExecSeq: 2, Filename: "/usr/lib/go/pkg/tool/compile", Role: residual.ExecRoleDescendant},
	)
	detectedSeq := seq + 1
	var out bytes.Buffer
	renderExecForest(&out, "/repo", "codex", residual.ExecutionEpisode{AncestryComplete: true, ExecMembers: members}, []actionview.Detection{{RelatedEventSeq: detectedSeq}}, false)
	text := out.String()
	if strings.Count(text, "compile ×3") != 2 {
		t.Fatalf("sibling groups crossed parent boundaries or were not grouped:\n%s", text)
	}
	if !strings.Contains(text, "⚠ compile  [descendant]") || !strings.Contains(text, "compile  [exec_replacement]") {
		t.Fatalf("detected/replacement nodes were grouped:\n%s", text)
	}
	if !strings.Contains(text, fmt.Sprintf("%d exec observations total", len(members))) || !strings.Contains(text, "use --verbose") {
		t.Fatalf("large tree total/hint missing:\n%s", text)
	}
}

func TestExecutableProvenanceQualifiers(t *testing.T) {
	for _, tc := range []struct {
		filename string
		want     string
	}{
		{"/repo/.fixtures/bin/git", "git (.fixtures/bin/git)"},
		{"/tmp/build/tool", "tool (/tmp/build/tool)"},
		{"/opt/vendor/tool", "tool (/opt/vendor/tool)"},
		{"/usr/bin/git", "git"},
	} {
		got := execDisplayName("/repo", residual.ExecMember{Filename: tc.filename}, false)
		if got != tc.want {
			t.Fatalf("execDisplayName(%q)=%q, want %q", tc.filename, got, tc.want)
		}
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

func TestInspectFileEffectsDeduplicatesOperationAndPathAcrossAttributionStates(t *testing.T) {
	episode := residual.ExecutionEpisode{FileEffects: []residual.FileEffect{
		{Seq: 1, Op: "modify", Path: "/repo/result", Attribution: "task_instance_latest_exec_generation"},
		{Seq: 2, Op: "truncate", Path: "/repo/result", Attribution: "task_instance_no_exec"},
	}}
	var out bytes.Buffer
	renderInspectFileEffects(&out, runs.Meta{CWD: "/repo"}, episode, nil, 10, false)
	if strings.Count(out.String(), "result") != 1 || !strings.Contains(out.String(), "(x2)") {
		t.Fatalf("operation/path group was split by attribution:\n%s", out.String())
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
	for _, want := range []string{"Agent actions  3", "2 matched · 1 mismatch", "#1  ✓ MATCHED", "#2  ✓ MATCHED", "#3  ✕ REPORTED_NOT_OBSERVED", "⚠ 1 MEDIUM detection", "network ⚠ partial", "inspect r action:1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("agent view missing %q:\n%s", want, text)
		}
	}
}

func TestRenderActionInspectionKeepsHighMatchCompactAndGroupsDetections(t *testing.T) {
	detections := []actionview.Detection{
		{Seq: 20, Severity: "medium", RuleID: "E1", Message: "same", RelatedEventSeq: 10},
		{Seq: 21, Severity: "MEDIUM", RuleID: "E1", Message: "same", RelatedEventSeq: 11},
		{Seq: 22, Severity: "low", RuleID: "F1", Message: "other", RelatedEventSeq: 12},
	}
	action := actionview.Action{
		Index: 1, RuntimeReport: actionview.RuntimeReport{Provider: "codex", Command: "pwd", Status: "completed"},
		Finding:    residual.Finding{Classification: residual.Matched, Confidence: "high", Reason: "exact deterministic match"},
		Detections: detections,
	}
	meta := runs.Meta{RunID: "r", Coverage: runs.Coverage{
		Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
		Process: runs.KernelCoverage{Capture: "complete"}, File: runs.KernelCoverage{Availability: "unavailable"}, Network: runs.KernelCoverage{Capture: "not_applicable"},
	}}
	var out bytes.Buffer
	renderActionInspection(&out, meta, action, 1, false, cliui.Colorizer{})
	text := out.String()
	for _, want := range []string{"✓ MATCHED · high confidence", "E1 same (x2)", "1 more detection group(s)", "file     unavailable", "network  not applicable"} {
		if !strings.Contains(text, want) {
			t.Fatalf("normal inspection missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "reason:") || strings.Contains(text, "related event seq=") {
		t.Fatalf("normal high-confidence inspection was too verbose:\n%s", text)
	}

	out.Reset()
	renderActionInspection(&out, meta, action, 1, true, cliui.Colorizer{})
	if !strings.Contains(out.String(), "reason: exact deterministic match") || strings.Count(out.String(), "related event seq=") != 3 {
		t.Fatalf("verbose inspection omitted exact evidence:\n%s", out.String())
	}
}

func TestRenderActionInspectionFiltersNeutralEpisodeCoverageWarning(t *testing.T) {
	episode := &residual.ExecutionEpisode{
		AncestryComplete: true, ProcessCapture: "complete", FileCapture: "complete", NetworkCapture: "not_applicable",
		AttributionIssues: []string{"network capture is not complete; attributed network effects may be incomplete"},
	}
	action := actionview.Action{
		Index: 1, RuntimeReport: actionview.RuntimeReport{Provider: "codex", Command: "pwd"}, Episode: episode,
		Finding: residual.Finding{Classification: residual.Matched, Confidence: "high", Reason: "matched with coverage context"},
	}
	meta := runs.Meta{RunID: "r", Coverage: runs.Coverage{
		Agent: runs.AgentCoverage{Capture: "complete", Interpretation: "complete"}, Process: runs.KernelCoverage{Capture: "complete"},
		File: runs.KernelCoverage{Capture: "complete"}, Network: runs.KernelCoverage{Capture: "not_applicable"},
	}}
	var out bytes.Buffer
	renderActionInspection(&out, meta, action, 10, false, cliui.Colorizer{})
	if strings.Contains(out.String(), "network capture is not complete") || strings.Contains(out.String(), "reason:") {
		t.Fatalf("neutral episode state rendered uncertainty:\n%s", out.String())
	}

	episode.NetworkCapture = "partial"
	meta.Coverage.Network.Capture = "partial"
	out.Reset()
	renderActionInspection(&out, meta, action, 10, false, cliui.Colorizer{})
	for _, want := range []string{"reason: matched with coverage context", "network capture is not complete", "network telemetry capture=partial"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("partial coverage missing %q:\n%s", want, out.String())
		}
	}
}

func TestCoveragePresentationStates(t *testing.T) {
	if got := kernelCoverageMark(runs.KernelCoverage{Capture: "not_applicable"}); got != "—" {
		t.Fatalf("not_applicable mark=%q", got)
	}
	if got := kernelCoverageMark(runs.KernelCoverage{Availability: "unavailable"}); got != "unavailable" {
		t.Fatalf("unavailable mark=%q", got)
	}
	if got := kernelCoverageMark(runs.KernelCoverage{Capture: "partial"}); got != "⚠ partial" {
		t.Fatalf("partial mark=%q", got)
	}
	if got := coverageValue("not_applicable"); got != "not applicable" {
		t.Fatalf("inspect coverage value=%q", got)
	}
	meta := runs.Meta{Coverage: runs.Coverage{Agent: runs.AgentCoverage{Capture: "complete", Interpretation: "unknown"}}}
	if got := agentCoverageMark(meta); got != "⚠ unknown" {
		t.Fatalf("unknown agent interpretation mark=%q", got)
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
