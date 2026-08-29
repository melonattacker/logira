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
		if signal := actionDetectionSignal(action.Detections); signal != "" {
			_, _ = fmt.Fprintf(w, "      %s\n", signal)
		}
		if action.Finding.Confidence != "" && action.Finding.Confidence != "high" {
			_, _ = fmt.Fprintf(w, "      confidence %s\n", action.Finding.Confidence)
		}
		warnings := action.CoverageWarnings
		if action.Episode != nil {
			warnings = actionview.EpisodeWarnings(*action.Episode)
		}
		if len(warnings) > 0 {
			_, _ = fmt.Fprintf(w, "      coverage warning: %s\n", cliui.Truncate(warnings[0], 110))
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
		symbol = "✓"
	case residual.ReportedNotObserved:
		symbol = "✕"
	case residual.Blocked:
		symbol = "■"
	case residual.Unobservable:
		symbol = "?"
	}
	label := symbol + " " + classification
	if clr.Enabled && action.Finding.Classification != residual.Matched {
		return clr.Warn(label)
	}
	return label
}

func agentCoverageMark(meta runs.Meta) string {
	if meta.Coverage.Agent.Capture == "complete" && meta.Coverage.Agent.Interpretation == "complete" {
		return "✓"
	}
	states := []string{meta.Coverage.Agent.Capture, meta.Coverage.Agent.Interpretation}
	for _, state := range states {
		normalized := strings.ToLower(strings.TrimSpace(state))
		if normalized != "complete" && normalized != "not_applicable" && normalized != "unavailable" {
			return coverageMark(state)
		}
	}
	for _, state := range states {
		if strings.EqualFold(strings.TrimSpace(state), "unavailable") {
			return "unavailable"
		}
	}
	return "—"
}

func kernelCoverageMark(coverage runs.KernelCoverage) string {
	state := kernelCoverageState(coverage)
	if state == "complete" {
		return "✓"
	}
	return coverageMark(state)
}

func kernelCoverageState(coverage runs.KernelCoverage) string {
	if strings.TrimSpace(coverage.Capture) != "" {
		return coverage.Capture
	}
	if strings.EqualFold(strings.TrimSpace(coverage.Availability), "unavailable") {
		return "unavailable"
	}
	return coverage.Capture
}

func coverageMark(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "complete":
		return "✓"
	case "not_applicable":
		return "—"
	case "unavailable":
		return "unavailable"
	case "partial":
		return "⚠ partial"
	case "":
		return "⚠ unknown"
	default:
		return "⚠ " + value
	}
}

func coverageValue(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "unknown"
	case "not_applicable":
		return "not applicable"
	default:
		return value
	}
}

type detectionGroupLocationInfo struct {
	Actions  map[int]struct{}
	RunLevel bool
}

func renderAgentDetectionGroups(w io.Writer, view actionview.Run, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) {
	var detections []actionview.Detection
	locations := make(map[string]*detectionGroupLocationInfo)
	add := func(d actionview.Detection, action int) {
		detections = append(detections, d)
		key := detectionPresentationKey(d)
		location := locations[key]
		if location == nil {
			location = &detectionGroupLocationInfo{Actions: make(map[int]struct{})}
			locations[key] = location
		}
		if action > 0 {
			location.Actions[action] = struct{}{}
		} else {
			location.RunLevel = true
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
	ordered := actionview.GroupDetections(detections)
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
		where := detectionGroupLocation(locations[detectionGroupKey(group)])
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

func detectionGroupLocation(group *detectionGroupLocationInfo) string {
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

func detectionPresentationKey(detection actionview.Detection) string {
	return strings.ToLower(strings.TrimSpace(detection.Severity)) + "\x00" + detection.RuleID + "\x00" + detection.Message
}

func detectionGroupKey(group actionview.DetectionGroup) string {
	return group.Severity + "\x00" + group.RuleID + "\x00" + group.Message
}

func actionDetectionSignal(detections []actionview.Detection) string {
	if len(detections) == 0 {
		return ""
	}
	highest := "unknown"
	weight := -1
	for _, detection := range detections {
		if candidate := severityWeight(detection.Severity); candidate > weight {
			weight = candidate
			highest = strings.ToUpper(strings.TrimSpace(detection.Severity))
			if highest == "" {
				highest = "UNKNOWN"
			}
		}
	}
	if len(detections) == 1 {
		return fmt.Sprintf("⚠ 1 %s detection", highest)
	}
	return fmt.Sprintf("⚠ %d detections · highest %s", len(detections), highest)
}

func detectionSummary(view actionview.Run) string {
	counts := make(map[string]int)
	total := 0
	for _, action := range view.Actions {
		for _, detection := range action.Detections {
			counts[strings.ToLower(strings.TrimSpace(detection.Severity))]++
			total++
		}
	}
	for _, detection := range view.RunLevelDetections {
		counts[strings.ToLower(strings.TrimSpace(detection.Severity))]++
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
