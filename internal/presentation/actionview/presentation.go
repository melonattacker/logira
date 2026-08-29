package actionview

import (
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/analyzer/residual"
)

// DetectionGroup is a presentation-only grouping of identical stored
// detections. Detections retains the exact records for evidence summaries.
type DetectionGroup struct {
	Severity   string
	RuleID     string
	Message    string
	Count      int
	FirstTS    int64
	LastTS     int64
	Detections []Detection
}

// GroupDetections groups only detections with the same normalized severity,
// exact rule ID, and exact message. Stored detection values are not modified.
func GroupDetections(detections []Detection) []DetectionGroup {
	type key struct {
		severity string
		ruleID   string
		message  string
	}
	byKey := make(map[key]int)
	groups := make([]DetectionGroup, 0, len(detections))
	for _, detection := range detections {
		severity := strings.ToLower(strings.TrimSpace(detection.Severity))
		k := key{severity: severity, ruleID: detection.RuleID, message: detection.Message}
		if index, ok := byKey[k]; ok {
			groups[index].Count++
			groups[index].Detections = append(groups[index].Detections, detection)
			if detection.TS < groups[index].FirstTS {
				groups[index].FirstTS = detection.TS
			}
			if detection.TS > groups[index].LastTS {
				groups[index].LastTS = detection.TS
			}
			continue
		}
		byKey[k] = len(groups)
		groups = append(groups, DetectionGroup{
			Severity: severity, RuleID: detection.RuleID, Message: detection.Message,
			Count: 1, FirstTS: detection.TS, LastTS: detection.TS, Detections: []Detection{detection},
		})
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if left, right := presentationSeverityWeight(groups[i].Severity), presentationSeverityWeight(groups[j].Severity); left != right {
			return left > right
		}
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		if groups[i].RuleID != groups[j].RuleID {
			return groups[i].RuleID < groups[j].RuleID
		}
		return groups[i].Message < groups[j].Message
	})
	return groups
}

func presentationSeverityWeight(value string) int {
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

// EpisodeWarnings filters capture-state boilerplate that would incorrectly
// present not-applicable or unavailable telemetry as an episode warning. The
// original episode remains unchanged for JSON output.
func EpisodeWarnings(episode residual.ExecutionEpisode) []string {
	out := make([]string, 0, len(episode.AttributionIssues))
	for _, issue := range episode.AttributionIssues {
		if strings.HasPrefix(issue, "process capture is not complete;") && neutralCapture(episode.ProcessCapture) {
			continue
		}
		if strings.HasPrefix(issue, "file capture is not complete;") && neutralCapture(episode.FileCapture) {
			continue
		}
		if strings.HasPrefix(issue, "network capture is not complete;") && neutralCapture(episode.NetworkCapture) {
			continue
		}
		out = append(out, issue)
	}
	return out
}

func neutralCapture(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "not_applicable", "unavailable":
		return true
	default:
		return false
	}
}
