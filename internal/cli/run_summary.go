package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/storage"
)

type runSummaryMode string

const (
	runSummaryModeAuto       runSummaryMode = "auto"
	runSummaryModeOff        runSummaryMode = "off"
	runSummaryModeDetections runSummaryMode = "detections"
)

type runEndSummary struct {
	RunID          string
	Duration       string
	ExitCode       int
	EventCounts    map[storage.EventType]int
	SeverityCounts map[string]int
	Risk           string
	TopDetections  []storage.GroupedDetection
}

func parseRunSummaryMode(v string) (runSummaryMode, error) {
	switch runSummaryMode(strings.ToLower(strings.TrimSpace(v))) {
	case runSummaryModeAuto:
		return runSummaryModeAuto, nil
	case runSummaryModeOff:
		return runSummaryModeOff, nil
	case runSummaryModeDetections:
		return runSummaryModeDetections, nil
	default:
		return "", fmt.Errorf("--summary must be one of auto, off, detections")
	}
}

func renderRunEndSummaryFromRun(w io.Writer, mode runSummaryMode, runID, runDir string, exitCode int) error {
	if mode == runSummaryModeOff {
		return nil
	}
	s, err := loadRunEndSummary(runID, runDir, exitCode)
	if err != nil {
		return err
	}
	return renderRunEndSummary(w, mode, s)
}

func loadRunEndSummary(runID, runDir string, exitCode int) (runEndSummary, error) {
	sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite"))
	if err != nil {
		return runEndSummary{}, err
	}
	defer func() {
		_ = sqlite.Close()
	}()

	row, err := sqlite.GetRunRow(runID)
	if err != nil {
		return runEndSummary{}, err
	}
	eventCounts, err := sqlite.CountEventsByType(runID)
	if err != nil {
		return runEndSummary{}, err
	}
	sevCounts, err := sqlite.CountDetectionsBySeverity(runID)
	if err != nil {
		return runEndSummary{}, err
	}
	top, err := sqlite.ListGroupedDetections(runID, 5)
	if err != nil {
		return runEndSummary{}, err
	}

	sevCounts = normalizeSeverityCounts(sevCounts)
	duration := "unknown"
	if row.StartTS > 0 && row.EndTS > 0 && row.EndTS >= row.StartTS {
		duration = cliui.FormatDuration(row.StartTS, row.EndTS)
	}

	return runEndSummary{
		RunID:          runID,
		Duration:       duration,
		ExitCode:       exitCode,
		EventCounts:    eventCounts,
		SeverityCounts: sevCounts,
		Risk:           runRisk(sevCounts),
		TopDetections:  top,
	}, nil
}

func normalizeSeverityCounts(in map[string]int) map[string]int {
	out := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	for k, v := range in {
		out[strings.ToLower(strings.TrimSpace(k))] = v
	}
	return out
}

func runRisk(sev map[string]int) string {
	sev = normalizeSeverityCounts(sev)
	switch {
	case sev["high"] > 0:
		return "HIGH"
	case sev["medium"] > 0:
		return "MEDIUM"
	case sev["low"]+sev["info"] > 0:
		return "LOW"
	default:
		return "NONE"
	}
}

func renderRunEndSummary(w io.Writer, mode runSummaryMode, s runEndSummary) error {
	if mode == runSummaryModeOff {
		return nil
	}
	sev := normalizeSeverityCounts(s.SeverityCounts)
	risk := strings.TrimSpace(s.Risk)
	if risk == "" {
		risk = runRisk(sev)
	}

	if _, err := fmt.Fprintf(w, "[logira] run %s finished in %s, exit=%d\n", s.RunID, s.Duration, s.ExitCode); err != nil {
		return err
	}
	if mode == runSummaryModeAuto {
		evt := s.EventCounts
		if evt == nil {
			evt = map[storage.EventType]int{}
		}
		if _, err := fmt.Fprintf(w, "  events:      %d exec, %d file, %d net\n", evt[storage.TypeExec], evt[storage.TypeFile], evt[storage.TypeNet]); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "  detections:  %d high, %d medium, %d low, %d info\n", sev["high"], sev["medium"], sev["low"], sev["info"]); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "  risk:        %s\n\n", risk); err != nil {
		return err
	}

	if _, err := fmt.Fprintln(w, "  top detections:"); err != nil {
		return err
	}
	if len(s.TopDetections) == 0 {
		if _, err := fmt.Fprintln(w, "    (none)"); err != nil {
			return err
		}
	} else {
		for _, d := range s.TopDetections {
			msg := cliui.Truncate(strings.TrimSpace(d.Message), 72)
			if d.Count > 1 {
				msg = fmt.Sprintf("%s (x%d)", msg, d.Count)
			}
			if _, err := fmt.Fprintf(w, "    %-6s %-8s %s\n", displayDetectionSeverity(d.Severity), cliui.Truncate(d.RuleID, 8), msg); err != nil {
				return err
			}
		}
	}

	_, err := fmt.Fprintf(w, "\n  next:\n    %s view %s\n    %s explain %s --show-related\n", progName(), s.RunID, progName(), s.RunID)
	return err
}

func displayDetectionSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high":
		return "HIGH"
	case "medium":
		return "MED"
	case "low":
		return "LOW"
	case "info":
		return "INFO"
	default:
		return strings.ToUpper(strings.TrimSpace(v))
	}
}
