package htmlreport

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/runs"
)

const (
	initialEffectGroups  = 12
	maxFileGroups        = 1000
	maxNetworkGroups     = 500
	maxDetectionEvidence = 20
)

type Report struct {
	RunID            string
	Command          string
	Duration         string
	Started          string
	Ended            string
	ActionCount      int
	Consistency      string
	DetectionSummary string
	Coverage         []CoverageItem
	CoverageWarnings []string
	Actions          []Action
	Detections       []DetectionGroup
	OtherCounts      []FindingCount
	OtherFindings    []Finding
}

type CoverageItem struct {
	Name  string
	Icon  string
	Value string
	Class string
}

type Action struct {
	Index               int
	Open                bool
	Command             string
	Status              string
	Exit                string
	Classification      string
	ClassificationIcon  string
	ClassificationClass string
	Confidence          string
	Reason              string
	RuntimeText         string
	RawTruncated        bool
	HasEpisode          bool
	ExecCount           int
	ProcessCount        int
	FileCount           int
	NetworkCount        int
	SecuritySummary     string
	SecurityClass       string
	CoverageWarnings    []string
	Episode             *Episode
	InspectCommand      string
	FileQueryCommand    string
	NetworkQueryCommand string
	DetectionCommand    string
}

type Episode struct {
	DefaultRoots            []*ExecutionNode
	FullRoots               []*ExecutionNode
	CollapsedInfrastructure int
	GroupedLeaves           int
	TotalExecs              int
	Large                   bool
	Ancestry                CoverageItem
	Coverage                []CoverageItem
	Files                   EffectSection[FileGroup]
	Networks                EffectSection[NetworkGroup]
	Detections              []DetectionGroup
}

type ExecutionNode struct {
	Label      string
	Role       string
	Executable string
	Detected   bool
	GroupCount int
	Seq        int64
	PID        int
	Generation int
	ParentSeq  int64
	CWD        string
	Filename   string
	Children   []*ExecutionNode
}

type EffectSection[T any] struct {
	Total        int
	GroupCount   int
	Initial      []T
	Expanded     []T
	Omitted      int
	HasExpansion bool
}

type FileGroup struct {
	Category              string
	Op                    string
	Path                  string
	Count                 int
	Detected              bool
	Workspace             bool
	AttributionIncomplete bool
}

type NetworkGroup struct {
	Op          string
	Proto       string
	Destination string
	Count       int
	Bytes       int64
	Detected    bool
	Unknown     bool
}

type DetectionGroup struct {
	Severity      string
	SeverityClass string
	RuleID        string
	Message       string
	Count         int
	Locations     string
	Evidence      []DetectionEvidence
	EvidenceMore  int
}

type DetectionEvidence struct {
	Seq     int64
	Type    string
	Summary string
}

type FindingCount struct {
	Classification string
	Count          int
}

type Finding struct {
	Classification string
	Confidence     string
	Reported       string
	Observed       string
	Reason         string
}

// Build derives only report presentation data from the shared action view.
func Build(view actionview.Run) Report {
	report := Report{
		RunID:            view.Meta.RunID,
		Command:          valueOr(view.Meta.Command, "-"),
		Duration:         formatDuration(view.Meta.StartTS, view.Meta.EndTS),
		Started:          formatTimestamp(view.Meta.StartTS),
		Ended:            formatTimestamp(view.Meta.EndTS),
		ActionCount:      len(view.Actions),
		Consistency:      consistencySummary(view.Report),
		DetectionSummary: detectionSummary(view),
		Coverage:         runCoverage(view.Meta),
		CoverageWarnings: reportCoverageWarnings(view.Meta, view.CoverageWarnings),
		Detections:       runDetectionGroups(view),
	}
	for _, source := range view.Actions {
		report.Actions = append(report.Actions, buildAction(view.Meta, source))
	}
	report.OtherCounts, report.OtherFindings = buildOtherFindings(view.OtherFindings)
	return report
}

func buildAction(meta runs.Meta, source actionview.Action) Action {
	action := Action{
		Index:               source.Index,
		Open:                source.Index == 1,
		Command:             source.RuntimeReport.Command,
		Status:              valueOr(source.RuntimeReport.Status, "unknown"),
		Classification:      string(source.Finding.Classification),
		ClassificationIcon:  classificationIcon(source.Finding.Classification),
		ClassificationClass: classificationClass(source.Finding.Classification),
		Confidence:          source.Finding.Confidence,
		Reason:              source.Finding.Reason,
		RuntimeText:         source.RuntimeReport.Text,
		RawTruncated:        source.RuntimeReport.RawTruncated,
		SecuritySummary:     actionSecuritySummary(source.Detections),
		SecurityClass:       severityClass(highestDetectionSeverity(source.Detections)),
		InspectCommand:      fmt.Sprintf("logira inspect %s action:%d --verbose", meta.RunID, source.Index),
		FileQueryCommand:    fmt.Sprintf("logira query %s --type file --all", meta.RunID),
		NetworkQueryCommand: fmt.Sprintf("logira query %s --type net --all", meta.RunID),
		DetectionCommand:    fmt.Sprintf("logira query %s --type detection --all", meta.RunID),
	}
	if source.RuntimeReport.ExitCode != nil {
		action.Exit = fmt.Sprintf("%d", *source.RuntimeReport.ExitCode)
	}
	warnings := append([]string(nil), source.CoverageWarnings...)
	if source.Episode != nil {
		warnings = actionview.EpisodeWarnings(*source.Episode)
	}
	action.CoverageWarnings = uniqueStrings(append(warnings, reportCoverageWarnings(meta, actionview.CoverageWarnings(meta))...))
	if source.Episode == nil {
		return action
	}
	action.HasEpisode = true
	summary := source.Episode.Summary
	action.ExecCount = summary.Execs
	action.ProcessCount = summary.Processes
	action.FileCount = summary.Files
	action.NetworkCount = summary.Networks
	action.Episode = buildEpisode(meta, source)
	return action
}

func buildEpisode(meta runs.Meta, source actionview.Action) *Episode {
	episode := source.Episode
	trees := actionview.BuildExecutionTrees(meta.CWD, source.RuntimeReport.Provider, *episode, source.Detections)
	ancestry := coverageItem("Ancestry", "complete", 0)
	if !episode.AncestryComplete {
		ancestry = CoverageItem{Name: "Ancestry", Icon: "?", Value: "incomplete", Class: "warning"}
	}
	coverage := append(runCoverage(meta), ancestry)
	return &Episode{
		DefaultRoots:            buildExecutionNodes(meta.CWD, trees.DefaultRoots),
		FullRoots:               buildExecutionNodes(meta.CWD, trees.FullRoots),
		CollapsedInfrastructure: trees.CollapsedInfrastructure,
		GroupedLeaves:           trees.GroupedLeafObservations,
		TotalExecs:              trees.TotalExecObservations,
		Large:                   trees.Large,
		Ancestry:                ancestry,
		Coverage:                coverage,
		Files:                   buildFileSection(meta.CWD, episode.FileEffects, source.Detections),
		Networks:                buildNetworkSection(episode.NetworkEffects, source.Detections),
		Detections:              detectionGroups(source.Detections, fmt.Sprintf("Action #%d", source.Index)),
	}
}

func buildExecutionNodes(workspaceRoot string, nodes []*actionview.ExecutionTreeNode) []*ExecutionNode {
	out := make([]*ExecutionNode, 0, len(nodes))
	for _, node := range nodes {
		member := node.Member
		label := actionview.ExecDisplayName(workspaceRoot, member, node.GroupCount == 0)
		out = append(out, &ExecutionNode{
			Label: label, Role: string(member.Role), Executable: actionview.ExecutableQualifier(workspaceRoot, member.Filename),
			Detected: node.Detected, GroupCount: node.GroupCount, Seq: member.Seq, PID: member.PID,
			Generation: member.Generation, ParentSeq: member.ParentExecSeq, CWD: member.CWD,
			Filename: member.Filename, Children: buildExecutionNodes(workspaceRoot, node.Children),
		})
	}
	return out
}

func buildFileSection(workspaceRoot string, effects []residual.FileEffect, detections []actionview.Detection) EffectSection[FileGroup] {
	groups := actionview.GroupFileEffects(workspaceRoot, effects, detections)
	sort.SliceStable(groups, func(i, j int) bool {
		if left, right := reportFilePriority(groups[i]), reportFilePriority(groups[j]); left != right {
			return left < right
		}
		if groups[i].Op != groups[j].Op {
			return groups[i].Op < groups[j].Op
		}
		return groups[i].Path < groups[j].Path
	})
	converted := make([]FileGroup, 0, min(len(groups), maxFileGroups))
	for _, group := range groups[:min(len(groups), maxFileGroups)] {
		converted = append(converted, FileGroup{
			Category: fileCategory(group), Op: group.Op, Path: group.Path, Count: group.Count,
			Detected: group.Detection, Workspace: group.Workspace, AttributionIncomplete: group.AttributionIncomplete,
		})
	}
	initial := converted[:min(len(converted), initialEffectGroups)]
	return EffectSection[FileGroup]{
		Total: len(effects), GroupCount: len(groups), Initial: initial, Expanded: converted,
		Omitted: len(groups) - len(converted), HasExpansion: len(groups) > len(initial),
	}
}

func reportFilePriority(group actionview.FileEffectGroup) int {
	if group.Detection {
		return 0
	}
	if group.Workspace && group.StateChanging {
		return 1
	}
	if group.StateChanging {
		return 2
	}
	if group.AttributionIncomplete {
		return 3
	}
	return 4
}

func fileCategory(group actionview.FileEffectGroup) string {
	switch reportFilePriority(group) {
	case 0:
		return "Highlighted"
	case 1:
		return "Workspace changes"
	case 2:
		return "Other changes"
	case 3:
		return "Uncertain attribution"
	default:
		return "Reads, chdirs, and other"
	}
}

func buildNetworkSection(effects []residual.NetworkEffect, detections []actionview.Detection) EffectSection[NetworkGroup] {
	groups := actionview.GroupNetworkEffects(effects, detections)
	converted := make([]NetworkGroup, 0, min(len(groups), maxNetworkGroups))
	for _, group := range groups[:min(len(groups), maxNetworkGroups)] {
		converted = append(converted, NetworkGroup{
			Op: group.Op, Proto: group.Proto, Destination: group.Destination, Count: group.Count,
			Bytes: group.Bytes, Detected: group.Detection, Unknown: group.Destination == "unknown",
		})
	}
	initial := converted[:min(len(converted), initialEffectGroups)]
	return EffectSection[NetworkGroup]{
		Total: len(effects), GroupCount: len(groups), Initial: initial, Expanded: converted,
		Omitted: len(groups) - len(converted), HasExpansion: len(groups) > len(initial),
	}
}

func runDetectionGroups(view actionview.Run) []DetectionGroup {
	all := make([]actionview.Detection, 0)
	locations := make(map[string]map[string]bool)
	add := func(d actionview.Detection, location string) {
		all = append(all, d)
		key := detectionKey(d.Severity, d.RuleID, d.Message)
		if locations[key] == nil {
			locations[key] = make(map[string]bool)
		}
		locations[key][location] = true
	}
	for _, action := range view.Actions {
		for _, detection := range action.Detections {
			add(detection, fmt.Sprintf("Action #%d", action.Index))
		}
	}
	for _, detection := range view.RunLevelDetections {
		add(detection, "Run-level")
	}
	groups := actionview.GroupDetections(all)
	out := make([]DetectionGroup, 0, len(groups))
	for _, group := range groups {
		where := make([]string, 0, len(locations[detectionKey(group.Severity, group.RuleID, group.Message)]))
		for location := range locations[detectionKey(group.Severity, group.RuleID, group.Message)] {
			where = append(where, location)
		}
		sort.Slice(where, func(i, j int) bool { return locationLess(where[i], where[j]) })
		out = append(out, convertDetectionGroup(group, strings.Join(where, ", ")))
	}
	return out
}

func detectionGroups(detections []actionview.Detection, location string) []DetectionGroup {
	groups := actionview.GroupDetections(detections)
	out := make([]DetectionGroup, 0, len(groups))
	for _, group := range groups {
		out = append(out, convertDetectionGroup(group, location))
	}
	return out
}

func convertDetectionGroup(group actionview.DetectionGroup, locations string) DetectionGroup {
	evidence := make([]DetectionEvidence, 0, min(len(group.Detections), maxDetectionEvidence))
	for _, detection := range group.Detections[:min(len(group.Detections), maxDetectionEvidence)] {
		item := DetectionEvidence{Seq: detection.RelatedEventSeq, Type: "unavailable", Summary: "Related event unavailable"}
		if detection.RelatedEvent != nil {
			item.Seq = detection.RelatedEvent.Seq
			item.Type = string(detection.RelatedEvent.Type)
			item.Summary = detection.RelatedEvent.Summary
		}
		evidence = append(evidence, item)
	}
	return DetectionGroup{
		Severity: strings.ToUpper(valueOr(group.Severity, "unknown")), SeverityClass: severityClass(group.Severity),
		RuleID: group.RuleID, Message: group.Message, Count: group.Count, Locations: locations,
		Evidence: evidence, EvidenceMore: len(group.Detections) - len(evidence),
	}
}

func buildOtherFindings(findings []residual.Finding) ([]FindingCount, []Finding) {
	counts := make(map[residual.Classification]int)
	out := make([]Finding, 0, len(findings))
	for _, finding := range findings {
		counts[finding.Classification]++
		out = append(out, Finding{
			Classification: string(finding.Classification), Confidence: finding.Confidence,
			Reported: finding.Command, Observed: finding.ExecSummary, Reason: finding.Reason,
		})
	}
	ordered := make([]FindingCount, 0, len(counts))
	for _, class := range []residual.Classification{
		residual.ObservedNotReported, residual.ReportedNotObserved, residual.Blocked, residual.Unobservable, residual.Matched,
	} {
		if counts[class] > 0 {
			ordered = append(ordered, FindingCount{Classification: string(class), Count: counts[class]})
		}
	}
	return ordered, out
}

func runCoverage(meta runs.Meta) []CoverageItem {
	return []CoverageItem{
		coverageItem("Agent capture", meta.Coverage.Agent.Capture, 0),
		coverageItem("Agent interpretation", meta.Coverage.Agent.Interpretation, 0),
		coverageItem("Process", kernelCoverageState(meta.Coverage.Process), meta.Coverage.Process.KnownLoss.Total()),
		coverageItem("File", kernelCoverageState(meta.Coverage.File), meta.Coverage.File.KnownLoss.Total()),
		coverageItem("Network", kernelCoverageState(meta.Coverage.Network), meta.Coverage.Network.KnownLoss.Total()),
	}
}

func coverageItem(name, state string, loss uint64) CoverageItem {
	normalized := strings.ToLower(strings.TrimSpace(state))
	item := CoverageItem{Name: name}
	switch normalized {
	case "complete":
		item.Icon, item.Value, item.Class = "✓", "complete", "good"
	case "not_applicable":
		item.Icon, item.Value, item.Class = "—", "not applicable", "neutral"
	case "unavailable":
		item.Icon, item.Value, item.Class = "?", "unavailable", "neutral"
	case "partial":
		item.Icon, item.Value, item.Class = "⚠", "partial", "warning"
	case "":
		item.Icon, item.Value, item.Class = "?", "unknown", "warning"
	default:
		item.Icon, item.Value, item.Class = "⚠", state, "warning"
	}
	if loss > 0 {
		item.Icon, item.Class = "⚠", "warning"
		item.Value += fmt.Sprintf(" · %d known lost", loss)
	}
	return item
}

func reportCoverageWarnings(meta runs.Meta, base []string) []string {
	out := append([]string(nil), base...)
	for _, item := range []struct {
		name string
		data runs.KernelCoverage
	}{{"process", meta.Coverage.Process}, {"file", meta.Coverage.File}, {"network", meta.Coverage.Network}} {
		state := strings.ToLower(strings.TrimSpace(kernelCoverageState(item.data)))
		if item.data.KnownLoss.Total() == 0 && (state == "complete" || state == "not_applicable" || state == "unavailable") {
			continue
		}
		out = append(out, fmt.Sprintf("Some %s telemetry was lost or incomplete; absence of an effect should not be interpreted as proof it did not occur.", item.name))
	}
	return uniqueStrings(out)
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

func consistencySummary(report residual.Report) string {
	parts := make([]string, 0, 4)
	if count := report.Counts[residual.Matched]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d matched", count))
	}
	if count := report.Counts[residual.ReportedNotObserved] + report.Counts[residual.ObservedNotReported]; count > 0 {
		parts = append(parts, fmt.Sprintf("%d mismatch", count))
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

func actionSecuritySummary(detections []actionview.Detection) string {
	if len(detections) == 0 {
		return "No attributed detections"
	}
	highest := strings.ToUpper(valueOr(highestDetectionSeverity(detections), "unknown"))
	if len(detections) == 1 {
		return fmt.Sprintf("1 %s detection", highest)
	}
	return fmt.Sprintf("%d detections · highest %s", len(detections), highest)
}

func highestDetectionSeverity(detections []actionview.Detection) string {
	highest, weight := "", -1
	for _, detection := range detections {
		if candidate := severityWeight(detection.Severity); candidate > weight {
			highest, weight = detection.Severity, candidate
		}
	}
	return strings.ToLower(strings.TrimSpace(highest))
}

func severityWeight(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func severityClass(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "severity-high"
	case "medium":
		return "severity-medium"
	case "low":
		return "severity-low"
	case "info":
		return "severity-info"
	default:
		return "neutral"
	}
}

func classificationIcon(classification residual.Classification) string {
	switch classification {
	case residual.Matched:
		return "✓"
	case residual.ReportedNotObserved, residual.ObservedNotReported:
		return "✕"
	case residual.Blocked:
		return "■"
	default:
		return "?"
	}
}

func classificationClass(classification residual.Classification) string {
	switch classification {
	case residual.Matched:
		return "good"
	case residual.ReportedNotObserved, residual.ObservedNotReported:
		return "danger"
	case residual.Blocked, residual.Unobservable:
		return "warning"
	default:
		return "neutral"
	}
}

func detectionKey(severity, ruleID, message string) string {
	return strings.ToLower(strings.TrimSpace(severity)) + "\x00" + ruleID + "\x00" + message
}

func locationLess(left, right string) bool {
	if left == "Run-level" {
		return false
	}
	if right == "Run-level" {
		return true
	}
	return left < right
}

func formatDuration(start, end int64) string {
	if start <= 0 || end <= 0 || end < start {
		return "unknown"
	}
	d := time.Duration(end - start)
	if d < time.Millisecond {
		return d.String()
	}
	return d.Round(time.Millisecond).String()
}

func formatTimestamp(value int64) string {
	if value <= 0 {
		return "unknown"
	}
	return time.Unix(0, value).UTC().Format("2006-01-02 15:04:05.000 UTC")
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
