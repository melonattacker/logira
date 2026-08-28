package actionview

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

// RuntimeReport contains only the normalized command_execution data already
// retained in the event stream. It is a runtime report, not trusted evidence.
type RuntimeReport struct {
	Provider     string `json:"provider"`
	ItemID       string `json:"item_id,omitempty"`
	Command      string `json:"command"`
	Status       string `json:"status,omitempty"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	Text         string `json:"text,omitempty"`
	AgentSeq     int64  `json:"agent_seq"`
	RawTruncated bool   `json:"raw_truncated,omitempty"`
}

type Detection struct {
	Seq             int64          `json:"seq"`
	TS              int64          `json:"ts"`
	RuleID          string         `json:"rule_id"`
	Severity        string         `json:"severity"`
	Message         string         `json:"message"`
	RelatedEventSeq int64          `json:"related_event_seq,omitempty"`
	RelatedEvent    *storage.Event `json:"related_event,omitempty"`
}

type Action struct {
	Index            int                        `json:"index"`
	ActionID         string                     `json:"action_id"`
	ItemID           string                     `json:"item_id,omitempty"`
	RuntimeReport    RuntimeReport              `json:"runtime_report"`
	Finding          residual.Finding           `json:"finding"`
	Episode          *residual.ExecutionEpisode `json:"episode,omitempty"`
	Detections       []Detection                `json:"detections,omitempty"`
	CoverageWarnings []string                   `json:"coverage_warnings,omitempty"`

	episodeIndex int
}

type Run struct {
	Meta               runs.Meta          `json:"meta"`
	Report             residual.Report    `json:"report"`
	Actions            []Action           `json:"actions"`
	OtherFindings      []residual.Finding `json:"other_findings,omitempty"`
	RunLevelDetections []Detection        `json:"run_level_detections,omitempty"`
	CoverageWarnings   []string           `json:"coverage_warnings,omitempty"`
}

type runtimeAction struct {
	report RuntimeReport
}

// Build analyzes a completed Codex run once and adds presentation-only runtime
// details and conservative detection attribution.
func Build(meta runs.Meta, events []storage.Event) (Run, error) {
	report := residual.Analyze(meta, events)
	out := Run{Meta: meta, Report: report, CoverageWarnings: runCoverageWarnings(meta)}
	runtimeActions := collectRuntimeActions(events)

	findingsByItem := make(map[string]int)
	findingsBySeq := make(map[int64]int)
	for i, finding := range report.Findings {
		if finding.AgentSeq <= 0 {
			out.OtherFindings = append(out.OtherFindings, finding)
			continue
		}
		if finding.ItemID != "" {
			findingsByItem[finding.ItemID] = i
		}
		findingsBySeq[finding.AgentSeq] = i
	}

	episodeByExec := make(map[int64]int)
	for i := range report.Episodes {
		episodeByExec[report.Episodes[i].DirectMatch.Seq] = i
	}
	for i, runtime := range runtimeActions {
		findingIndex, ok := findingsBySeq[runtime.report.AgentSeq]
		if runtime.report.ItemID != "" {
			findingIndex, ok = findingsByItem[runtime.report.ItemID]
		}
		if !ok {
			return Run{}, fmt.Errorf("command_execution seq=%d item=%q has no residual finding", runtime.report.AgentSeq, runtime.report.ItemID)
		}
		finding := report.Findings[findingIndex]
		actionID := runtime.report.ItemID
		if actionID == "" {
			actionID = fmt.Sprintf("agent-seq:%d", runtime.report.AgentSeq)
		}
		action := Action{
			Index: i + 1, ActionID: actionID, ItemID: runtime.report.ItemID,
			RuntimeReport: runtime.report, Finding: finding, episodeIndex: -1,
		}
		if episodeIndex, exists := episodeByExec[finding.ExecSeq]; exists {
			action.episodeIndex = episodeIndex
			episode := report.Episodes[episodeIndex]
			action.Episode = &episode
			action.CoverageWarnings = append(action.CoverageWarnings, episode.AttributionIssues...)
		}
		out.Actions = append(out.Actions, action)
	}

	attributeDetections(&out, events)
	return out, nil
}

func collectRuntimeActions(events []storage.Event) []runtimeAction {
	byKey := make(map[string]int)
	out := make([]runtimeAction, 0)
	for _, event := range events {
		if event.Type != storage.TypeAgent {
			continue
		}
		var detail model.AgentDetail
		if json.Unmarshal(event.DataJSON, &detail) != nil || detail.Kind != "command_execution" {
			continue
		}
		if detail.Provider != "" && detail.Provider != "codex" {
			continue
		}
		key := detail.ItemID
		if key == "" {
			key = fmt.Sprintf("seq:%d", event.Seq)
		}
		index, exists := byKey[key]
		if !exists {
			index = len(out)
			byKey[key] = index
			out = append(out, runtimeAction{report: RuntimeReport{
				Provider: "codex", ItemID: detail.ItemID, Command: detail.Command,
				Status: detail.Status, ExitCode: detail.ExitCode, Text: detail.Text,
				AgentSeq: event.Seq, RawTruncated: detail.RawTruncated,
			}})
			continue
		}
		report := &out[index].report
		if detail.Command != "" {
			report.Command = detail.Command
		}
		if detail.Status != "" {
			report.Status = detail.Status
		}
		if detail.ExitCode != nil {
			report.ExitCode = detail.ExitCode
		}
		if detail.Text != "" {
			report.Text = detail.Text
		}
		report.RawTruncated = report.RawTruncated || detail.RawTruncated
	}
	filtered := out[:0]
	for _, action := range out {
		if strings.TrimSpace(action.report.Command) != "" {
			filtered = append(filtered, action)
		}
	}
	return filtered
}

func attributeDetections(run *Run, events []storage.Event) {
	memberships := make(map[int64]map[int]struct{})
	add := func(seq int64, episodeIndex int) {
		if seq <= 0 {
			return
		}
		if memberships[seq] == nil {
			memberships[seq] = make(map[int]struct{})
		}
		memberships[seq][episodeIndex] = struct{}{}
	}
	for episodeIndex, episode := range run.Report.Episodes {
		add(episode.AgentSeq, episodeIndex)
		for _, member := range episode.ExecMembers {
			add(member.Seq, episodeIndex)
		}
		for _, member := range episode.ProcessMembers {
			add(member.ForkSeq, episodeIndex)
			add(member.ExitSeq, episodeIndex)
		}
		for _, effect := range episode.FileEffects {
			add(effect.Seq, episodeIndex)
		}
		for _, effect := range episode.NetworkEffects {
			add(effect.Seq, episodeIndex)
		}
	}

	bySeq := make(map[int64]storage.Event, len(events))
	for _, event := range events {
		bySeq[event.Seq] = event
	}
	episodeToAction := make(map[int]int)
	for actionIndex := range run.Actions {
		if run.Actions[actionIndex].episodeIndex >= 0 {
			episodeToAction[run.Actions[actionIndex].episodeIndex] = actionIndex
		}
	}

	for _, event := range events {
		if event.Type != storage.TypeDetection {
			continue
		}
		var stored storage.Detection
		if json.Unmarshal(event.DataJSON, &stored) != nil {
			continue
		}
		detection := Detection{
			Seq: event.Seq, TS: event.TS, RuleID: stored.RuleID, Severity: stored.Severity,
			Message: stored.Message, RelatedEventSeq: stored.RelatedEventSeq,
		}
		if related, ok := bySeq[stored.RelatedEventSeq]; ok && stored.RelatedEventSeq > 0 {
			relatedCopy := related
			detection.RelatedEvent = &relatedCopy
		}
		membership := memberships[stored.RelatedEventSeq]
		if len(membership) == 1 {
			for episodeIndex := range membership {
				if actionIndex, ok := episodeToAction[episodeIndex]; ok {
					run.Actions[actionIndex].Detections = append(run.Actions[actionIndex].Detections, detection)
					goto attributed
				}
			}
		}
		run.RunLevelDetections = append(run.RunLevelDetections, detection)
	attributed:
	}
}

func runCoverageWarnings(meta runs.Meta) []string {
	warnings := make([]string, 0, 4)
	if meta.Coverage.Agent.Capture != "complete" || meta.Coverage.Agent.Interpretation != "complete" {
		warnings = append(warnings, fmt.Sprintf("agent telemetry capture=%s interpretation=%s", valueOrUnknown(meta.Coverage.Agent.Capture), valueOrUnknown(meta.Coverage.Agent.Interpretation)))
	}
	for _, item := range []struct {
		name string
		data runs.KernelCoverage
	}{{"process", meta.Coverage.Process}, {"file", meta.Coverage.File}, {"network", meta.Coverage.Network}} {
		if item.data.Capture != "complete" {
			warnings = append(warnings, fmt.Sprintf("%s telemetry capture=%s", item.name, valueOrUnknown(item.data.Capture)))
		}
	}
	return warnings
}

func valueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func (run *Run) ResolveAction(selector string) (*Action, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil, fmt.Errorf("empty action selector")
	}
	if ordinal, err := strconv.Atoi(selector); err == nil {
		if ordinal < 1 || ordinal > len(run.Actions) {
			return nil, fmt.Errorf("action ordinal %d is out of range (run has %d actions)", ordinal, len(run.Actions))
		}
		return &run.Actions[ordinal-1], nil
	}
	for i := range run.Actions {
		if run.Actions[i].ActionID == selector || run.Actions[i].ItemID == selector {
			return &run.Actions[i], nil
		}
	}
	return nil, fmt.Errorf("action %q not found (use an ordinal from 'logira view' or an exact item ID)", selector)
}
