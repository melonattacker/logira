package htmlreport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analysis/episode"
	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func reportEvent(t *testing.T, seq int64, typ storage.EventType, detail any) storage.Event {
	t.Helper()
	b, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	return storage.Event{RunID: "r", Seq: seq, TS: 1_000_000_000 + seq, Type: typ, Summary: fmt.Sprintf("%s %d", typ, seq), DataJSON: b}
}

func richReportInput(t *testing.T, attack string, withEpisode bool) BuildInput {
	t.Helper()
	events := []storage.Event{
		reportEvent(t, 1, storage.TypeExec, model.ExecDetail{Filename: "/bin/sh", Argv: []string{"sh", "-c", attack}, TID: 10, TGID: 10, TaskStartKernelNS: 10, KernelTimeNS: 20}),
		reportEvent(t, 2, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTGID: 10, ParentTaskStartKernelNS: 10, ChildTID: 11, ChildTGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 31, CloneKind: "unknown"}),
		reportEvent(t, 3, storage.TypeFile, model.FileDetail{Op: "create_or_open", Syscall: "openat", Correlation: "complete", Path: "/tmp/" + attack, RawPath: attack, PathResolution: "unresolved", Flags: 64, ReturnValue: 4, TID: 11, TGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 40}),
		reportEvent(t, 4, storage.TypeNet, model.NetDetail{Op: "connect", Proto: "udp", DstIP: "203.0.113.4", DstPort: 443, ConnectState: "in_progress", TID: 11, TGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 41}),
		reportEvent(t, 5, storage.TypeExec, model.ExecDetail{Filename: "/bin/tool", Argv: []string{"tool", "arg"}, TID: 10, TGID: 10, TaskStartKernelNS: 10, KernelTimeNS: 50}),
	}
	detection := reportEvent(t, 6, storage.TypeDetection, storage.Detection{RuleID: "R1", Severity: "high", Message: attack, RelatedEventSeq: 3})
	detection.Summary = attack
	events = append(events, detection)
	g, err := processgraph.Build("r", events)
	if err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{RunID: "r", StartTS: 1_000_000_000, EndTS: 2_000_000_000, Command: attack, CommandArgv: []string{"audit", attack}, CWD: "/repo", Version: 5,
		Coverage: runs.Coverage{DeliveryDrain: "snapshot", Process: runs.KernelCoverage{Availability: "available", Capture: "unknown"}, File: runs.KernelCoverage{Availability: "available", Capture: "partial", KnownLoss: runs.KnownLoss{SessionQueueDropped: 2}}, Network: runs.KernelCoverage{Availability: "available", Capture: "unknown"}}}
	in := BuildInput{RunID: "r", Meta: meta, MetadataSource: "meta.json", EventSource: "jsonl", Events: events, Graph: g}
	if withEpisode {
		ep, err := episode.Build(meta, 1, g)
		if err != nil {
			t.Fatal(err)
		}
		ep.AnalysisSource.Events, ep.AnalysisSource.Metadata = "jsonl", "meta.json"
		in.Episode = &ep
	}
	return in
}

func TestRunOverviewDoesNotSelectEpisode(t *testing.T) {
	report, err := Build(richReportInput(t, "normal", false))
	if err != nil {
		t.Fatal(err)
	}
	if report.Episode != nil || report.Run.Mode != "Run Overview" {
		t.Fatalf("overview selected an Episode: %+v", report.Episode)
	}
	if report.Run.Counts.Exec != 2 || report.Run.Counts.File != 1 || report.Run.Counts.Network != 1 || report.ExecTotal != 2 {
		t.Fatalf("unexpected overview counts: %+v", report.Run.Counts)
	}
	if report.Coverage[1].KnownLoss != 2 || report.Coverage[1].Class != "warning" {
		t.Fatalf("coverage loss hidden: %+v", report.Coverage[1])
	}
}

func TestCoverageStatesRemainReportedAndUnverified(t *testing.T) {
	complete := coverageItem("Process", runs.KernelCoverage{Availability: "available", Capture: "complete"})
	if complete.Availability != "available" || complete.Capture != "complete" {
		t.Fatalf("reported coverage values changed: %+v", complete)
	}
	if complete.Class != "reported" || !strings.Contains(complete.Interpretation, "not independently verified") {
		t.Fatalf("complete capture was presented as verified: %+v", complete)
	}

	unavailable := coverageItem("File", runs.KernelCoverage{Availability: "unavailable", Capture: "not_applicable"})
	if unavailable.Class != "warning" || !strings.Contains(unavailable.Interpretation, "not reported available") {
		t.Fatalf("unavailable collection was not called out: %+v", unavailable)
	}

	lossy := coverageItem("Network", runs.KernelCoverage{Availability: "available", Capture: "complete", KnownLoss: runs.KnownLoss{CollectorForwardDropped: 3}})
	if lossy.Class != "warning" || lossy.KnownLoss != 3 || !strings.Contains(lossy.LossDetail, "collector_forward_dropped=3") || !strings.Contains(lossy.Interpretation, "known collection or persistence loss") || !strings.Contains(lossy.Interpretation, "not independently verified") {
		t.Fatalf("known loss was not called out: %+v", lossy)
	}
}

func TestEpisodeKeepsTaskAndEvidenceSemantics(t *testing.T) {
	report, err := Build(richReportInput(t, "normal", true))
	if err != nil {
		t.Fatal(err)
	}
	ep := report.Episode
	if ep == nil || ep.TaskTotal != 2 || len(ep.Tasks) != 2 {
		t.Fatalf("episode tasks=%+v", ep)
	}
	var forkOnly *TaskRow
	for i := range ep.Tasks {
		if ep.Tasks[i].ForkOnly {
			forkOnly = &ep.Tasks[i]
		}
	}
	if forkOnly == nil || len(forkOnly.Execs) != 0 || forkOnly.CloneKind != "unknown" || forkOnly.Incoming != "confirmed observed fork" {
		t.Fatalf("fork-only semantics changed: %+v", forkOnly)
	}
	if len(ep.Tasks[0].Execs) != 2 || ep.Tasks[0].Execs[0].Seq != 1 || ep.Tasks[0].Execs[1].Seq != 5 {
		t.Fatalf("exec replacements were not retained on one task: %+v", ep.Tasks[0].Execs)
	}
	if ep.FileCounts.Attributed != 1 || ep.NetworkCounts.Attributed != 1 || ep.File.Groups[0].Operation != "create_or_open" || ep.File.Groups[0].PathResolution != "unresolved" {
		t.Fatalf("file semantics changed: %+v %+v", ep.FileCounts, ep.File.Groups)
	}
	if ep.Network.Groups[0].Protocol != "udp" || ep.Network.Groups[0].State != "in_progress" {
		t.Fatalf("network semantics changed: %+v", ep.Network.Groups[0])
	}
	if got := report.Detections[0].Evidence[0].LinkState; got != "References attributed Episode evidence" {
		t.Fatalf("detection link=%q", got)
	}
}

func TestNonLeaderRekeyRemainsOneTaskWithAliases(t *testing.T) {
	events := []storage.Event{
		reportEvent(t, 1, storage.TypeExec, model.ExecDetail{Filename: "/bin/leader", TID: 10, TGID: 10, TaskStartKernelNS: 10, KernelTimeNS: 20}),
		reportEvent(t, 2, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTaskStartKernelNS: 10, ChildTID: 11, ChildTGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 31, CloneKind: "thread_clone"}),
		reportEvent(t, 3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", OldPID: 11, TID: 10, TGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 51}),
		reportEvent(t, 4, storage.TypeExec, model.ExecDetail{Filename: "/bin/rekeyed", OldPID: 11, TID: 10, TGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 50}),
	}
	g, err := processgraph.Build("r", events)
	if err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{RunID: "r", EndTS: 100}
	ep, err := episode.Build(meta, 4, g)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Build(BuildInput{RunID: "r", Meta: meta, MetadataSource: "meta.json", EventSource: "jsonl", Events: events, Graph: g, Episode: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if report.Episode.TaskTotal != 1 || len(report.Episode.Tasks) != 1 {
		t.Fatalf("rekey was rendered as a new child: %+v", report.Episode.Tasks)
	}
	row := report.Episode.Tasks[0]
	if row.RekeySeqs != "3" || !strings.Contains(row.Identities, "tid=11") || !strings.Contains(row.Identities, "tid=10") || len(row.Execs) != 1 || row.Execs[0].Filename != "/bin/rekeyed" {
		t.Fatalf("rekey identity continuity lost: %+v", row)
	}
}

func TestUncertainEvidenceStaysOutOfAttributedTables(t *testing.T) {
	root := reportEvent(t, 1, storage.TypeExec, model.ExecDetail{Filename: "/bin/root"})
	root.PID = 10
	child := reportEvent(t, 2, storage.TypeExec, model.ExecDetail{Filename: "/bin/candidate"})
	child.PID, child.PPID = 20, 10
	file := reportEvent(t, 3, storage.TypeFile, model.FileDetail{Op: "open", Path: "candidate"})
	file.PID = 20
	events := []storage.Event{root, child, file}
	g, err := processgraph.Build("r", events)
	if err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{RunID: "r", EndTS: 100}
	ep, err := episode.Build(meta, 1, g)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Build(BuildInput{RunID: "r", Meta: meta, MetadataSource: "meta.json", EventSource: "jsonl", Events: events, Graph: g, Episode: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if report.Episode.File.Observed != 0 || len(report.Episode.File.Groups) != 0 || report.Episode.Uncertain.Observed != 1 || len(report.Episode.Uncertain.Groups) != 1 {
		t.Fatalf("uncertain evidence was mixed with attributed evidence: %+v", report.Episode)
	}
}

func TestStandaloneHTMLIsEscapedDeterministicAndOffline(t *testing.T) {
	attack := `</style><script src="https://evil.invalid/x.js">alert(1)</script><img src=x onerror=alert(2)>`
	report, err := Build(richReportInput(t, attack, true))
	if err != nil {
		t.Fatal(err)
	}
	var first, second bytes.Buffer
	if err := Render(&first, report); err != nil {
		t.Fatal(err)
	}
	if err := Render(&second, report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("rendering is not deterministic")
	}
	html := first.String()
	if strings.Count(strings.ToLower(html), "<!doctype html>") != 1 || strings.Count(strings.ToLower(html), "<html") != 1 {
		t.Fatal("output is not exactly one HTML document")
	}
	if strings.Contains(html, attack) || strings.Contains(strings.ToLower(html), "<script") || strings.Contains(strings.ToLower(html), "<img") {
		t.Fatal("hostile markup was emitted as executable HTML")
	}
	for _, want := range []string{"&lt;script", "Content-Security-Policy", "@media(max-width:620px)", "@media print", "default-src 'none'", "JSONL and SQLite remain the source of truth", "min-width:900px", "overflow-x:auto", "overscroll-behavior-inline:contain", "word-break:normal"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML missing %q", want)
		}
	}
	for _, forbidden := range []string{" href=", "<link", "<script", "<img", "@import", "url("} {
		if strings.Contains(strings.ToLower(html), forbidden) {
			t.Fatalf("standalone HTML contains %q", forbidden)
		}
	}
}

func TestRenderedCoverageDoesNotClaimCompleteCaptureSuccess(t *testing.T) {
	in := richReportInput(t, "normal", false)
	in.Meta.Coverage.Process = runs.KernelCoverage{Availability: "available", Capture: "complete"}
	in.Meta.Coverage.File = runs.KernelCoverage{Availability: "unavailable", Capture: "not_applicable"}
	in.Meta.Coverage.Network = runs.KernelCoverage{Availability: "available", Capture: "partial", KnownLoss: runs.KnownLoss{PersistenceFailures: 2}}
	report, err := Build(in)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := Render(&out, report); err != nil {
		t.Fatal(err)
	}
	html := out.String()
	for _, want := range []string{
		`class="coverage reported"`,
		`capture: <code>complete</code>`,
		"not independently verified",
		`availability: <code>unavailable</code>`,
		"persistence_failures=2",
	} {
		if !strings.Contains(html, want) {
			t.Fatalf("rendered coverage missing %q", want)
		}
	}
	if strings.Contains(html, `class="coverage good"`) {
		t.Fatal("reported complete capture was rendered as a green success state")
	}
}

func TestDeepLineageIsIterativeAndExplicitlyCapped(t *testing.T) {
	const descendants = maxTaskRows + 25
	events := []storage.Event{reportEvent(t, 1, storage.TypeExec, model.ExecDetail{Filename: "/bin/root", TID: 10, TGID: 10, TaskStartKernelNS: 10, KernelTimeNS: 20})}
	parent, parentBirth := 10, uint64(10)
	for i := 0; i < descendants; i++ {
		seq := int64(2 + i)
		child := 100 + i
		birth := uint64(30 + i*10)
		events = append(events, reportEvent(t, seq, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: parent, ParentTaskStartKernelNS: parentBirth, ChildTID: child, TaskStartKernelNS: birth, KernelTimeNS: birth + 1, CloneKind: "process_fork"}))
		parent, parentBirth = child, birth
	}
	g, err := processgraph.Build("r", events)
	if err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{RunID: "r", EndTS: 10}
	ep, err := episode.Build(meta, 1, g)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Build(BuildInput{RunID: "r", Meta: meta, MetadataSource: "meta.json", EventSource: "jsonl", Events: events, Graph: g, Episode: &ep})
	if err != nil {
		t.Fatal(err)
	}
	if report.Episode.TaskTotal != descendants+1 || len(report.Episode.Tasks) != maxTaskRows || report.Episode.TaskOmitted != 26 {
		t.Fatalf("deep tree limits=%d/%d omitted=%d", len(report.Episode.Tasks), report.Episode.TaskTotal, report.Episode.TaskOmitted)
	}
	if report.Episode.Tasks[len(report.Episode.Tasks)-1].DepthNote == "" {
		t.Fatal("deep visual indentation cap was not disclosed")
	}
}

func TestMalformedDetectionFailsClearly(t *testing.T) {
	in := richReportInput(t, "normal", false)
	in.Events[len(in.Events)-1].DataJSON = json.RawMessage(`{"message":`)
	if _, err := Build(in); err == nil || !strings.Contains(err.Error(), "seq 6") {
		t.Fatalf("malformed detection error=%v", err)
	}
}
