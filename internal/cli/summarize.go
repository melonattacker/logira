package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/logging"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

// SummarizeCommand is deprecated. Use `logira view`.
func SummarizeCommand(ctx context.Context, args []string) error {
	fmt.Fprintln(os.Stderr, "warning: 'summarize' is deprecated; use 'view' instead")

	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var logPath string
	var asJSON bool
	fs.StringVar(&logPath, "log", "", "deprecated: run directory or run id")
	fs.BoolVar(&asJSON, "json", false, "emit JSON summary (mapped to view --json)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sel := "last"
	if strings.TrimSpace(logPath) != "" {
		if fi, err := os.Stat(logPath); err == nil && !fi.IsDir() {
			return summarizeLogFile(logPath, asJSON)
		}

		// Accept either run id or a path to ~/.logira/runs/<id>.
		if strings.Contains(logPath, string(os.PathSeparator)) {
			sel = filepath.Base(filepath.Clean(logPath))
		} else {
			sel = strings.TrimSpace(logPath)
		}
	}

	viewArgs := []string{}
	if asJSON {
		viewArgs = append(viewArgs, "--json")
	}
	viewArgs = append(viewArgs, sel)
	return ViewCommand(ctx, viewArgs)
}

func summarizeLogFile(path string, asJSON bool) error {
	evs, err := readAnyStoredEvents(path)
	if err != nil {
		return err
	}

	runID := "legacy"
	if len(evs) > 0 && strings.TrimSpace(evs[0].RunID) != "" {
		runID = evs[0].RunID
	}

	timeline := evs
	if len(timeline) > 500 {
		timeline = timeline[:500]
	}
	dets := storage.Filter(evs, storage.QueryOptions{Type: storage.TypeDetection, Limit: 500})
	topExec := topExecFromEvents(evs, 20)
	topPaths := topPathsFromEvents(evs, 20)
	topDest := topDestinationsFromEvents(evs, 20)
	fileOps := fileOpsFromEvents(evs, 20)

	out := struct {
		Source       string            `json:"source"`
		RunID        string            `json:"run_id"`
		Timeline     []storage.Event   `json:"timeline"`
		Detections   []storage.Event   `json:"detections"`
		TopCommands  []storage.TopPair `json:"top_commands"`
		FileOps      []storage.TopPair `json:"file_ops"`
		ChangedFiles []storage.TopPair `json:"changed_files"`
		Destinations []storage.TopPair `json:"destinations"`
	}{
		Source:       path,
		RunID:        runID,
		Timeline:     timeline,
		Detections:   dets,
		TopCommands:  topExec,
		FileOps:      fileOps,
		ChangedFiles: topPaths,
		Destinations: topDest,
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Fprintf(os.Stdout, "Log: %s\n", path)
	fmt.Fprintf(os.Stdout, "Run: %s\n", runID)
	fmt.Fprintf(os.Stdout, "Detections: %d\n", len(dets))

	fmt.Fprintf(os.Stdout, "\nTimeline:\n")
	for _, ev := range timeline {
		ts := time.Unix(0, ev.TS).UTC().Format(time.RFC3339Nano)
		switch ev.Type {
		case storage.TypeExec:
			d, _ := parseExecDetail(ev.DataJSON)
			fmt.Fprintf(os.Stdout, "%s exec pid=%d ppid=%d %s argv=%v\n", ts, ev.PID, ev.PPID, d.Filename, d.Argv)
		case storage.TypeFile:
			d, _ := parseFileDetail(ev.DataJSON)
			fmt.Fprintf(os.Stdout, "%s file pid=%d op=%s path=%s\n", ts, ev.PID, d.Op, d.Path)
		case storage.TypeNet:
			d, _ := parseNetDetail(ev.DataJSON)
			fmt.Fprintf(os.Stdout, "%s net  pid=%d op=%s dst=%s:%d bytes=%d\n", ts, ev.PID, d.Op, d.DstIP, d.DstPort, d.Bytes)
		case storage.TypeDetection:
			var det storage.Detection
			_ = json.Unmarshal(ev.DataJSON, &det)
			fmt.Fprintf(os.Stdout, "%s DETECTION %s sev=%s related_seq=%d msg=%s\n", ts, det.RuleID, det.Severity, det.RelatedEventSeq, det.Message)
		default:
			fmt.Fprintf(os.Stdout, "%s %s %s\n", ts, ev.Type, ev.Summary)
		}
	}

	fmt.Fprintf(os.Stdout, "\nDetections:\n")
	if len(dets) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
	} else {
		for _, ev := range dets {
			ts := time.Unix(0, ev.TS).UTC().Format(time.RFC3339Nano)
			var det storage.Detection
			_ = json.Unmarshal(ev.DataJSON, &det)
			fmt.Fprintf(os.Stdout, "%s %s sev=%s related_seq=%d %s\n", ts, det.RuleID, det.Severity, det.RelatedEventSeq, det.Message)
		}
	}

	printTopPairs("Top Commands", topExec)
	printTopPairs("File Ops", fileOps)
	printTopPairs("Changed Files", topPaths)
	printTopPairs("Destinations", topDest)
	return nil
}

func readAnyStoredEvents(path string) ([]storage.Event, error) {
	if evs, err := storage.ReadJSONL(path); err == nil {
		return evs, nil
	} else {
		v1, rerr := logging.ReadEvents([]string{path})
		if rerr != nil {
			return nil, fmt.Errorf("read %s as v2: %v; as v1: %w", path, err, rerr)
		}
		return v1ToStoredEvents(v1), nil
	}
}

func v1ToStoredEvents(in []collector.Event) []storage.Event {
	out := make([]storage.Event, 0, len(in))
	for i, ev := range in {
		seq := int64(i + 1)

		var ts int64
		if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(ev.Timestamp)); err == nil {
			ts = t.UTC().UnixNano()
		}

		typ := storage.EventType(strings.TrimSpace(ev.Type))
		summary := strings.TrimSpace(ev.Type)
		switch typ {
		case storage.TypeExec:
			var d model.ExecDetail
			_ = json.Unmarshal(ev.Detail, &d)
			summary = execSummary(d)
		case storage.TypeFile:
			var d model.FileDetail
			_ = json.Unmarshal(ev.Detail, &d)
			summary = fmt.Sprintf("file %s %s", d.Op, d.Path)
		case storage.TypeNet:
			var d model.NetDetail
			_ = json.Unmarshal(ev.Detail, &d)
			summary = fmt.Sprintf("net %s %s:%d bytes=%d", d.Op, d.DstIP, d.DstPort, d.Bytes)
		}

		out = append(out, storage.Event{
			RunID:    "legacy",
			Seq:      seq,
			TS:       ts,
			Type:     typ,
			PID:      ev.PID,
			PPID:     ev.PPID,
			UID:      ev.UID,
			Summary:  summary,
			DataJSON: ev.Detail,
		})
	}
	return out
}
