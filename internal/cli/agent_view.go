package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/runs"
)

func viewAgentRun(runID, runDir string, meta runs.Meta, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) error {
	events, err := readResidualEvents(runID, runDir)
	if err != nil {
		return err
	}
	view, err := actionview.Build(meta, events)
	if err != nil {
		return fmt.Errorf("build agent action view: %w", err)
	}
	renderAgentRunView(os.Stdout, view, limit, tsMode, clr)
	return nil
}

func renderAgentRunView(w io.Writer, view actionview.Run, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) {
	if limit <= 0 {
		limit = 10
	}
	separator := strings.Repeat("─", 60)
	command := strings.TrimSpace(view.Meta.Command)
	if command == "" {
		command = "-"
	}
	_, _ = fmt.Fprintf(w, "Logira Run  %s\n%s\n", view.Meta.RunID, separator)
	_, _ = fmt.Fprintf(w, "%s\n\n", cliui.Truncate(command, 120))
	_, _ = fmt.Fprintf(w, "Duration       %s\n", cliui.FormatDuration(view.Meta.StartTS, view.Meta.EndTS))
	_, _ = fmt.Fprintf(w, "Agent actions  %d\n", len(view.Actions))
	_, _ = fmt.Fprintf(w, "Consistency    %s\n", consistencySummary(view.Report))
	_, _ = fmt.Fprintf(w, "Detections     %s\n", detectionSummary(view))
	_, _ = fmt.Fprintf(w, "Coverage       agent %s  process %s  file %s  network %s\n",
		agentCoverageMark(view.Meta), kernelCoverageMark(view.Meta.Coverage.Process),
		kernelCoverageMark(view.Meta.Coverage.File), kernelCoverageMark(view.Meta.Coverage.Network))
	for _, warning := range view.CoverageWarnings {
		_, _ = fmt.Fprintf(w, "               ! %s\n", warning)
	}

	_, _ = fmt.Fprintf(w, "\nAgent actions\n%s\n", separator)
	if len(view.Actions) == 0 {
		_, _ = fmt.Fprintln(w, "  (no Codex command_execution actions captured)")
	}
	for _, action := range view.Actions {
		label := actionClassificationLabel(action, clr)
		_, _ = fmt.Fprintf(w, "  #%d  %-28s %s\n", action.Index, label, cliui.Truncate(action.RuntimeReport.Command, 92))
		if action.Episode != nil {
			s := action.Episode.Summary
			_, _ = fmt.Fprintf(w, "      exec %d · process %d · file %d · net %d\n", s.Execs, s.Processes, s.Files, s.Networks)
		}
		if len(action.Detections) > 0 {
			_, _ = fmt.Fprintf(w, "      detections %d\n", len(action.Detections))
		}
		if action.Finding.Confidence != "" && action.Finding.Confidence != "high" {
			_, _ = fmt.Fprintf(w, "      confidence %s\n", action.Finding.Confidence)
		}
		if len(action.CoverageWarnings) > 0 {
			_, _ = fmt.Fprintf(w, "      coverage warning: %s\n", cliui.Truncate(action.CoverageWarnings[0], 110))
		}
		_, _ = fmt.Fprintln(w)
	}

	_, _ = fmt.Fprintf(w, "Other observations\n%s\n", separator)
	if len(view.OtherFindings) == 0 {
		_, _ = fmt.Fprintln(w, "  (none)")
	} else {
		counts := make(map[residual.Classification]int)
		for _, finding := range view.OtherFindings {
			counts[finding.Classification]++
		}
		for _, class := range []residual.Classification{
			residual.ObservedNotReported, residual.ReportedNotObserved, residual.Blocked, residual.Unobservable, residual.Matched,
		} {
			if counts[class] > 0 {
				_, _ = fmt.Fprintf(w, "  %-24s %d\n", class, counts[class])
			}
		}
	}

	renderAgentDetectionGroups(w, view, limit, tsMode, clr)
	_, _ = fmt.Fprintln(w, "\nNext:")
	if len(view.Actions) > 0 {
		_, _ = fmt.Fprintf(w, "  %s inspect %s action:1\n", progName(), view.Meta.RunID)
	}
	_, _ = fmt.Fprintf(w, "  %s query %s --type detection\n", progName(), view.Meta.RunID)
}

func consistencySummary(report residual.Report) string {
	parts := make([]string, 0, 4)
	if count := report.Counts[residual.Matched]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d matched", count))
	}
	mismatches := report.Counts[residual.ReportedNotObserved] + report.Counts[residual.ObservedNotReported]
	if mismatches > 0 {
		parts = append(parts, fmt.Sprintf("%d mismatch", mismatches))
	}
	if count := report.Counts[residual.Blocked]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", count))
	}
	if count := report.Counts[residual.Unobservable]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d unobservable", count))
	}
	if len(parts) == 0 {
		return "no findings"
	}
	return strings.Join(parts, " · ")
}

func actionClassificationLabel(action actionview.Action, clr cliui.Colorizer) string {
	classification := string(action.Finding.Classification)
	symbol := "?"
	switch action.Finding.Classification {
	case residual.Matched:
		if len(action.Detections) > 0 {
			symbol = "⚠"
		} else {
			symbol = "✓"
		}
	case residual.ReportedNotObserved:
		symbol = "✕"
	case residual.Blocked:
		symbol = "■"
	case residual.Unobservable:
		symbol = "?"
	}
	label := symbol + " " + classification
	if clr.Enabled && (action.Finding.Classification != residual.Matched || len(action.Detections) > 0) {
		return clr.Warn(label)
	}
	return label
}

func agentCoverageMark(meta runs.Meta) string {
	if meta.Coverage.Agent.Capture == "complete" && meta.Coverage.Agent.Interpretation == "complete" {
		return "✓"
	}
	return coverageValue(meta.Coverage.Agent.Capture)
}

func kernelCoverageMark(coverage runs.KernelCoverage) string {
	if coverage.Capture == "complete" {
		return "✓"
	}
	return coverageValue(coverage.Capture)
}

func coverageValue(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

type detectionGroup struct {
	Severity string
	RuleID   string
	Message  string
	Count    int
	FirstTS  int64
	Actions  map[int]struct{}
	RunLevel bool
}

func renderAgentDetectionGroups(w io.Writer, view actionview.Run, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) {
	groups := make(map[string]*detectionGroup)
	add := func(d actionview.Detection, action int) {
		key := d.Severity + "\x00" + d.RuleID + "\x00" + d.Message
		group := groups[key]
		if group == nil {
			group = &detectionGroup{Severity: d.Severity, RuleID: d.RuleID, Message: d.Message, FirstTS: d.TS, Actions: make(map[int]struct{})}
			groups[key] = group
		}
		group.Count++
		if d.TS < group.FirstTS {
			group.FirstTS = d.TS
		}
		if action > 0 {
			group.Actions[action] = struct{}{}
		} else {
			group.RunLevel = true
		}
	}
	for _, action := range view.Actions {
		for _, detection := range action.Detections {
			add(detection, action.Index)
		}
	}
	for _, detection := range view.RunLevelDetections {
		add(detection, 0)
	}
	ordered := make([]*detectionGroup, 0, len(groups))
	for _, group := range groups {
		ordered = append(ordered, group)
	}
	sort.Slice(ordered, func(i, j int) bool {
		left, right := severityWeight(ordered[i].Severity), severityWeight(ordered[j].Severity)
		if left != right {
			return left > right
		}
		if ordered[i].Count != ordered[j].Count {
			return ordered[i].Count > ordered[j].Count
		}
		return ordered[i].RuleID < ordered[j].RuleID
	})
	_, _ = fmt.Fprintf(w, "\nDetections\n%s\n", strings.Repeat("─", 60))
	if len(ordered) == 0 {
		_, _ = fmt.Fprintln(w, "  (none)")
		return
	}
	shown := len(ordered)
	if shown > limit {
		shown = limit
	}
	for _, group := range ordered[:shown] {
		where := detectionGroupLocation(group)
		severity := strings.ToUpper(group.Severity)
		if clr.Enabled {
			severity = clr.Severity(severity)
		}
		_, _ = fmt.Fprintf(w, "  %-8s %-10s %s", severity, cliui.Truncate(group.RuleID, 10), cliui.Truncate(group.Message, 66))
		if group.Count > 1 {
			_, _ = fmt.Fprintf(w, " (x%d)", group.Count)
		}
		_, _ = fmt.Fprintf(w, "\n      %s · %s\n", where, cliui.FormatTimestamp(group.FirstTS, view.Meta.StartTS, tsMode))
	}
	if shown < len(ordered) {
		_, _ = fmt.Fprintf(w, "  ... %d more detection group(s); use query --type detection\n", len(ordered)-shown)
	}
}

func detectionGroupLocation(group *detectionGroup) string {
	indexes := make([]int, 0, len(group.Actions))
	for index := range group.Actions {
		indexes = append(indexes, index)
	}
	sort.Ints(indexes)
	parts := make([]string, 0, len(indexes)+1)
	for _, index := range indexes {
		parts = append(parts, fmt.Sprintf("action #%d", index))
	}
	if group.RunLevel {
		parts = append(parts, "run-level")
	}
	return strings.Join(parts, ", ")
}

func detectionSummary(view actionview.Run) string {
	counts := make(map[string]int)
	total := 0
	for _, action := range view.Actions {
		for _, detection := range action.Detections {
			counts[detection.Severity]++
			total++
		}
	}
	for _, detection := range view.RunLevelDetections {
		counts[detection.Severity]++
		total++
	}
	if total == 0 {
		return "none"
	}
	parts := []string{fmt.Sprintf("%d total", total)}
	for _, severity := range []string{"high", "medium", "low", "info"} {
		if counts[severity] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[severity], severity))
		}
	}
	return strings.Join(parts, " · ")
}
