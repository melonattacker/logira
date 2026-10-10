package htmlreport

import (
	"bytes"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func TestReportRendersActionFirstCompressedEvidenceAndSeparateDimensions(t *testing.T) {
	view := richView("normal")
	report := Build(view)
	if len(report.Actions) != 2 || !report.Actions[0].Open || report.Actions[1].Open {
		t.Fatalf("unexpected action disclosure defaults: %+v", report.Actions)
	}
	first := report.Actions[0]
	if first.Classification != "MATCHED" || !strings.Contains(first.SecuritySummary, "HIGH") {
		t.Fatalf("consistency/security were not separate: %+v", first)
	}
	if first.Episode == nil || first.Episode.CollapsedInfrastructure != 2 || len(first.Episode.FullRoots) == 0 {
		t.Fatalf("execution expansion missing: %+v", first.Episode)
	}
	if first.Episode.Files.GroupCount != 14 || len(first.Episode.Files.Initial) != 12 || !first.Episode.Files.HasExpansion {
		t.Fatalf("file grouping limits missing: %+v", first.Episode.Files)
	}
	if len(report.Detections) != 1 || report.Detections[0].Count != 2 || len(report.Detections[0].Evidence) != 2 {
		t.Fatalf("repeated detection was not grouped: %+v", report.Detections)
	}

	var out bytes.Buffer
	if err := Render(&out, report); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{
		"Consistency", "✓ MATCHED", "Security", "2 detections · highest HIGH", "Show full execution tree",
		".fixtures/bin/git", "Show grouped file evidence", "not applicable", "Some file telemetry was lost or incomplete",
		"logira inspect run-1 action:1 --verbose", "JSONL and SQLite remain the source of truth",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("report missing %q", want)
		}
	}
}

func TestReportEscapesAllUntrustedTextAndHasNoExternalResources(t *testing.T) {
	attack := `<script>alert(1)</script>`
	view := richView(attack)
	view.Meta.Command = attack
	view.Actions[0].RuntimeReport.Command = attack
	view.Actions[0].RuntimeReport.Text = attack
	view.Actions[0].Episode.FileEffects[0].Path = "/repo/" + attack
	view.Actions[0].Detections[0].Message = attack
	view.Actions[0].Detections[0].RelatedEvent.Summary = attack

	var first, second bytes.Buffer
	report := Build(view)
	if err := Render(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := Render(&second, report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("report generation was not deterministic")
	}
	html := first.String()
	if strings.Contains(html, attack) || strings.Contains(strings.ToLower(html), "<script") {
		t.Fatalf("untrusted script was executable:\n%s", html)
	}
	if strings.Count(html, "&lt;script&gt;alert(1)&lt;/script&gt;") < 4 {
		t.Fatalf("untrusted values were not rendered as escaped text:\n%s", html)
	}
	for _, forbidden := range []string{" src=", " href=", "<link", "@import", "http://", "https://"} {
		if strings.Contains(strings.ToLower(html), forbidden) {
			t.Fatalf("standalone report contains external-resource marker %q", forbidden)
		}
	}
	if !strings.Contains(html, "Content-Security-Policy") {
		t.Fatal("report is missing its restrictive CSP")
	}
}

func TestCoverageStatesKeepNotApplicableNeutralAndLossVisible(t *testing.T) {
	view := richView("coverage")
	report := Build(view)
	states := make(map[string]CoverageItem)
	for _, item := range report.Coverage {
		states[item.Name] = item
	}
	if states["Network"].Value != "not applicable" || states["Network"].Class != "neutral" {
		t.Fatalf("not_applicable was presented as failure: %+v", states["Network"])
	}
	if states["File"].Class != "warning" || !strings.Contains(states["File"].Value, "known lost") {
		t.Fatalf("known loss was hidden: %+v", states["File"])
	}
}

func richView(text string) actionview.Run {
	meta := runs.Meta{
		RunID: "run-1", StartTS: 1_000_000_000, EndTS: 3_000_000_000, Command: "codex exec --json test", CWD: "/repo", AgentProvider: "codex",
		Coverage: runs.Coverage{
			Agent:   runs.AgentCoverage{Capture: "complete", Interpretation: "complete"},
			Process: runs.KernelCoverage{Capture: "complete"},
			File:    runs.KernelCoverage{Capture: "partial", KnownLoss: runs.KnownLoss{SessionQueueDropped: 1}},
			Network: runs.KernelCoverage{Capture: "not_applicable"},
		},
	}
	exit := 0
	fileEffects := make([]residual.FileEffect, 0, 15)
	for i := 0; i < 14; i++ {
		fileEffects = append(fileEffects, residual.FileEffect{Seq: int64(100 + i), Op: "open", Path: "/repo/path-" + string(rune('a'+i)), Attribution: "task_instance_latest_exec_generation"})
	}
	fileEffects[0].Op = "modify"
	fileEffects[0].Path = "/repo/marker"
	fileEffects = append(fileEffects, residual.FileEffect{Seq: 200, Op: "truncate", Path: "/repo/marker", Attribution: "task_instance_no_exec"})
	episode := &residual.ExecutionEpisode{
		AncestryComplete: true, ProcessCapture: "complete", FileCapture: "partial", NetworkCapture: "not_applicable",
		Summary: residual.EpisodeSummary{Execs: 5, Processes: 3, Files: len(fileEffects)}, FileEffects: fileEffects,
		ExecMembers: []residual.ExecMember{
			{Seq: 1, Filename: "/home/u/.codex/tmp/codex-linux-sandbox", Role: residual.ExecRoleWrapper},
			{Seq: 2, ParentExecSeq: 1, Filename: "/usr/bin/bwrap", Role: residual.ExecRoleWrapper},
			{Seq: 3, ParentExecSeq: 2, Filename: "/bin/bash", Argv: []string{"bash", "-c", "git status"}, Role: residual.ExecRoleDirectMatch},
			{Seq: 4, ParentExecSeq: 3, Filename: "/repo/.fixtures/bin/git", Role: residual.ExecRoleDescendant},
			{Seq: 5, ParentExecSeq: 4, Filename: "/usr/bin/git", Role: residual.ExecRoleExecReplacement},
		},
	}
	related1 := storage.Event{Seq: 100, Type: storage.TypeFile, Summary: "modify /repo/marker"}
	related2 := storage.Event{Seq: 200, Type: storage.TypeFile, Summary: "modify /repo/marker"}
	detections := []actionview.Detection{
		{Seq: 300, Severity: "high", RuleID: "F001", Message: text, RelatedEventSeq: 100, RelatedEvent: &related1},
		{Seq: 301, Severity: "HIGH", RuleID: "F001", Message: text, RelatedEventSeq: 200, RelatedEvent: &related2},
	}
	return actionview.Run{
		Meta:   meta,
		Report: residual.Report{Counts: map[residual.Classification]int{residual.Matched: 1, residual.Blocked: 1}},
		Actions: []actionview.Action{
			{Index: 1, RuntimeReport: actionview.RuntimeReport{Provider: "codex", Command: "git status", Status: "completed", ExitCode: &exit, Text: text}, Finding: residual.Finding{Classification: residual.Matched, Confidence: "high", Reason: "runtime command correlated with kernel exec"}, Episode: episode, Detections: detections},
			{Index: 2, RuntimeReport: actionview.RuntimeReport{Provider: "codex", Command: "blocked command", Status: "declined"}, Finding: residual.Finding{Classification: residual.Blocked, Confidence: "high", Reason: "runtime status declined"}},
		},
		OtherFindings:    []residual.Finding{{Classification: residual.ObservedNotReported, ExecSummary: "exec helper", Reason: "not associated with an action"}},
		CoverageWarnings: actionview.CoverageWarnings(meta),
	}
}
