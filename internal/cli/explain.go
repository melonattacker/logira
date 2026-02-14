package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/melonattacker/agentlogix/internal/runs"
	"github.com/melonattacker/agentlogix/internal/storage"
)

func ExplainCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sel := "last"
	if fs.NArg() > 0 {
		sel = fs.Arg(0)
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	runID, runDir, err := runs.ResolveRunID(home, sel)
	if err != nil {
		return err
	}
	meta, _ := runs.ReadMeta(runDir)

	var dets []storage.Event
	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()
		dets, err = sqlite.Query(storage.QueryOptions{RunID: runID, Type: storage.TypeDetection, Limit: 2000})
		if err != nil {
			return err
		}
	} else {
		all, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
		if rerr != nil {
			return fmt.Errorf("open sqlite: %v; read events.jsonl: %w", err, rerr)
		}
		dets = storage.Filter(all, storage.QueryOptions{RunID: runID, Type: storage.TypeDetection, Limit: 2000})
	}

	sevCounts := map[string]int{}
	for _, ev := range dets {
		var det storage.Detection
		_ = json.Unmarshal(ev.DataJSON, &det)
		sevCounts[det.Severity]++
	}

	type outJSON struct {
		RunID      string         `json:"run_id"`
		StartTS    int64          `json:"start_ts"`
		EndTS      int64          `json:"end_ts"`
		Command    string         `json:"command"`
		Suspicious int            `json:"suspicious_count"`
		Severities map[string]int `json:"severities"`
		Text       string         `json:"text"`
	}

	// meta.SuspiciousCount can be unset if a run ended abruptly; infer from dets.
	if meta.SuspiciousCount == 0 && len(dets) > 0 {
		meta.SuspiciousCount = len(dets)
	}
	text := buildExplainText(meta, dets, sevCounts)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(outJSON{
			RunID:      runID,
			StartTS:    meta.StartTS,
			EndTS:      meta.EndTS,
			Command:    meta.Command,
			Suspicious: meta.SuspiciousCount,
			Severities: sevCounts,
			Text:       text,
		})
	}

	fmt.Fprintln(os.Stdout, text)
	return nil
}

func buildExplainText(meta runs.Meta, detEvents []storage.Event, sevCounts map[string]int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Run %s\n", meta.RunID)
	if meta.StartTS > 0 {
		fmt.Fprintf(&b, "Start: %s\n", time.Unix(0, meta.StartTS).UTC().Format(time.RFC3339))
	}
	if meta.EndTS > 0 {
		fmt.Fprintf(&b, "End:   %s\n", time.Unix(0, meta.EndTS).UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(meta.Command) != "" {
		fmt.Fprintf(&b, "Cmd:   %s\n", meta.Command)
	}

	fmt.Fprintf(&b, "\nDetections: %d\n", meta.SuspiciousCount)
	if meta.SuspiciousCount == 0 {
		b.WriteString("No detections were produced by the built-in rules.\n")
		return b.String()
	}

	sevOrder := []string{"high", "medium", "low", "info"}
	for _, s := range sevOrder {
		if c := sevCounts[s]; c > 0 {
			fmt.Fprintf(&b, "- %s: %d\n", s, c)
		}
	}

	sort.Slice(detEvents, func(i, j int) bool {
		if detEvents[i].TS == detEvents[j].TS {
			return detEvents[i].Seq < detEvents[j].Seq
		}
		return detEvents[i].TS < detEvents[j].TS
	})
	b.WriteString("\nHighlights:\n")
	for i, ev := range detEvents {
		if i >= 10 {
			break
		}
		var det storage.Detection
		_ = json.Unmarshal(ev.DataJSON, &det)
		ts := time.Unix(0, ev.TS).UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(&b, "- %s %s sev=%s related_seq=%d: %s\n", ts, det.RuleID, det.Severity, det.RelatedEventSeq, det.Message)
	}
	return b.String()
}
