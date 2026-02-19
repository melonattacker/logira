package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func ExplainCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("explain", args, explainUsage)

	var (
		asJSON      bool
		raw         bool
		showRelated bool
		all         bool
		noColor     bool
		colorS      string
		limit       int
		drillSeq    int64
		tsModeS     string
	)
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.BoolVar(&raw, "raw", false, "emit legacy text output")
	fs.BoolVar(&showRelated, "show-related", false, "list each detection with related event")
	fs.Int64Var(&drillSeq, "drill", 0, "show one detection by seq with expanded related event")
	fs.IntVar(&limit, "limit", 0, "max rows")
	fs.BoolVar(&all, "all", false, "disable truncation and limits")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&colorS, "color", "auto", "color mode: auto|always|never")
	fs.StringVar(&tsModeS, "ts", "rel", "timestamp mode: abs|rel|both")
	if err := fs.Parse(args); err != nil {
		return err
	}
	tsMode, err := cliui.ParseTSMode(tsModeS)
	if err != nil {
		return err
	}
	colorMode, err := cliui.ParseColorMode(colorS)
	if err != nil {
		return err
	}
	if all {
		limit = 100000
	} else if limit <= 0 {
		if showRelated {
			limit = 20
		} else {
			limit = 10
		}
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

	if asJSON || raw {
		return explainLegacy(runID, runDir, meta, asJSON)
	}

	clr := cliui.NewColorizer(colorMode, noColor, os.Stdout)
	var (
		runStartTS int64 = meta.StartTS
		runEndTS   int64 = meta.EndTS
		command          = strings.TrimSpace(meta.Command)
	)
	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()
		if row, err := sqlite.GetRunRow(runID); err == nil {
			if runStartTS == 0 {
				runStartTS = row.StartTS
			}
			if runEndTS == 0 {
				runEndTS = row.EndTS
			}
			if command == "" {
				command = strings.TrimSpace(row.Command)
			}
		}
		if drillSeq > 0 {
			return explainDrillSQLite(runID, drillSeq, sqlite, runStartTS)
		}
		if showRelated {
			return explainShowRelatedSQLite(runID, sqlite, runStartTS, runEndTS, command, limit, all, tsMode, clr)
		}
		return explainGroupedSQLite(runID, sqlite, runStartTS, runEndTS, command, limit, tsMode, clr)
	}

	// Fallback path: JSONL only.
	allEvents, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if rerr != nil {
		return fmt.Errorf("read events.jsonl: %w", rerr)
	}
	allEvents = storage.Filter(allEvents, storage.QueryOptions{RunID: runID})
	if drillSeq > 0 {
		return explainDrillFallback(runID, drillSeq, allEvents, runStartTS)
	}
	if showRelated {
		return explainShowRelatedFallback(runID, allEvents, runStartTS, runEndTS, command, limit, all, tsMode, clr)
	}
	return explainGroupedFallback(runID, allEvents, runStartTS, runEndTS, command, limit, tsMode, clr)
}

func explainGroupedSQLite(runID string, sqlite *storage.SQLite, runStartTS, runEndTS int64, command string, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) error {
	groups, err := sqlite.ListGroupedDetections(runID, limit)
	if err != nil {
		return err
	}
	sevCounts, err := sqlite.CountDetectionsBySeverity(runID)
	if err != nil {
		return err
	}
	total := sevCounts["info"] + sevCounts["low"] + sevCounts["medium"] + sevCounts["high"]
	dur := "running"
	if runStartTS > 0 && runEndTS > 0 && runEndTS >= runStartTS {
		dur = cliui.FormatDuration(runStartTS, runEndTS)
	}
	fmt.Fprintf(os.Stdout, "Run %s  dur=%s  detections=%d (info=%d low=%d med=%d high=%d)  cmd=%q\n\n",
		runID, dur, total, sevCounts["info"], sevCounts["low"], sevCounts["medium"], sevCounts["high"], cliui.Truncate(command, 80))
	fmt.Fprintln(os.Stdout, "Detections (grouped)")
	if len(groups) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
	} else {
		rows := make([][]string, 0, len(groups))
		for _, g := range groups {
			sample := "-"
			if g.SampleRelatedSeq > 0 {
				if ev, err := sqlite.GetEventBySeq(runID, g.SampleRelatedSeq); err == nil {
					sample = fmt.Sprintf("seq=%d %s", g.SampleRelatedSeq, evidenceFromEvent(ev, 40))
				} else {
					sample = fmt.Sprintf("seq=%d", g.SampleRelatedSeq)
				}
			}
			sev := g.Severity
			if clr.Enabled {
				sev = clr.Severity(g.Severity)
			}
			rows = append(rows, []string{
				sev,
				cliui.Truncate(g.RuleID, 12),
				fmt.Sprintf("%d", g.Count),
				cliui.Truncate(g.Message, 48),
				cliui.FormatTimestamp(g.FirstTS, runStartTS, tsMode),
				cliui.FormatTimestamp(g.LastTS, runStartTS, tsMode),
				cliui.Truncate(sample, 44),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "sev", MaxWidth: 6},
			{Name: "rule", MaxWidth: 12},
			{Name: "count", MaxWidth: 5, AlignRight: true},
			{Name: "message", MaxWidth: 48},
			{Name: "first", MaxWidth: 18},
			{Name: "last", MaxWidth: 18},
			{Name: "sample_related", MaxWidth: 44},
		}, rows)
	}

	fmt.Fprintln(os.Stdout, "\nHints:")
	fmt.Fprintf(os.Stdout, "- %s explain %s --show-related\n", progName(), runID)
	fmt.Fprintf(os.Stdout, "- %s explain %s --drill <seq>\n", progName(), runID)
	fmt.Fprintf(os.Stdout, "- %s explain %s --raw\n", progName(), runID)
	return nil
}

func explainShowRelatedSQLite(runID string, sqlite *storage.SQLite, runStartTS, runEndTS int64, command string, limit int, all bool, tsMode cliui.TSMode, clr cliui.Colorizer) error {
	rows, err := sqlite.ListDetectionsWithRelated(runID, limit, 0)
	if err != nil {
		return err
	}
	sevCounts, err := sqlite.CountDetectionsBySeverity(runID)
	if err != nil {
		return err
	}
	total := sevCounts["info"] + sevCounts["low"] + sevCounts["medium"] + sevCounts["high"]
	dur := "running"
	if runStartTS > 0 && runEndTS > 0 && runEndTS >= runStartTS {
		dur = cliui.FormatDuration(runStartTS, runEndTS)
	}
	fmt.Fprintf(os.Stdout, "Run %s  dur=%s  detections=%d  cmd=%q\n\n", runID, dur, total, cliui.Truncate(command, 80))
	fmt.Fprintln(os.Stdout, "Detections (with related evidence)")
	if len(rows) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
		return nil
	}

	maxEvidence := 56
	if all {
		maxEvidence = 100000
	}
	tableRows := make([][]string, 0, len(rows))
	for _, r := range rows {
		evType := "-"
		evPID := "-"
		evidence := "-"
		if r.RelatedEventSeen {
			evType = string(r.RelatedType)
			evPID = fmt.Sprintf("%d", r.RelatedPID)
			ev := storage.Event{
				RunID:    runID,
				Seq:      r.RelatedSeq,
				TS:       r.RelatedTS,
				Type:     r.RelatedType,
				PID:      r.RelatedPID,
				Summary:  r.RelatedSummary,
				DataJSON: r.RelatedDataJSON,
			}
			evidence = evidenceFromEvent(ev, maxEvidence)
		}
		sev := r.Severity
		if clr.Enabled {
			sev = clr.Severity(r.Severity)
		}
		tableRows = append(tableRows, []string{
			sev,
			cliui.Truncate(r.RuleID, 10),
			fmt.Sprintf("%d", r.DetSeq),
			cliui.FormatTimestamp(r.DetTS, runStartTS, tsMode),
			fmt.Sprintf("%d", r.RelatedSeq),
			evType,
			evPID,
			evidence,
		})
	}
	cliui.RenderTable(os.Stdout, []cliui.Column{
		{Name: "sev", MaxWidth: 6},
		{Name: "rule", MaxWidth: 10},
		{Name: "det_seq", MaxWidth: 7, AlignRight: true},
		{Name: "at", MaxWidth: 18},
		{Name: "related_seq", MaxWidth: 11, AlignRight: true},
		{Name: "type", MaxWidth: 10},
		{Name: "pid", MaxWidth: 6, AlignRight: true},
		{Name: "evidence", MaxWidth: maxEvidence},
	}, tableRows)
	return nil
}

func explainDrillSQLite(runID string, seq int64, sqlite *storage.SQLite, runStartTS int64) error {
	det, err := sqlite.GetDetectionBySeq(runID, seq)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("detection seq=%d not found in run %s", seq, runID)
		}
		return err
	}
	fmt.Fprintf(os.Stdout, "Run %s\n", runID)
	fmt.Fprintf(os.Stdout, "Detection\n")
	fmt.Fprintf(os.Stdout, "  seq=%d ts=%s sev=%s rule=%s related_seq=%d\n", det.Seq, cliui.FormatAbsFull(det.TS), det.Severity, det.RuleID, det.RelatedSeq)
	fmt.Fprintf(os.Stdout, "  message=%s\n\n", det.Message)
	if det.RelatedSeq <= 0 {
		fmt.Fprintln(os.Stdout, "Related event: (none)")
		return nil
	}
	ev, err := sqlite.GetEventBySeq(runID, det.RelatedSeq)
	if err != nil {
		if err == sql.ErrNoRows {
			fmt.Fprintf(os.Stdout, "Related event seq=%d not found\n", det.RelatedSeq)
			return nil
		}
		return err
	}
	fmt.Fprintf(os.Stdout, "Related event\n")
	fmt.Fprintf(os.Stdout, "  seq=%d ts=%s rel=%s type=%s pid=%d\n", ev.Seq, cliui.FormatAbsFull(ev.TS), cliui.FormatRel(ev.TS, runStartTS), ev.Type, ev.PID)
	fmt.Fprintf(os.Stdout, "  summary=%s\n", ev.Summary)
	fmt.Fprintf(os.Stdout, "  evidence=%s\n", evidenceFromEvent(ev, 100000))
	return nil
}

func explainGroupedFallback(runID string, allEvents []storage.Event, runStartTS, runEndTS int64, command string, limit int, tsMode cliui.TSMode, clr cliui.Colorizer) error {
	dets := storage.Filter(allEvents, storage.QueryOptions{RunID: runID, Type: storage.TypeDetection})
	sevCounts := countDetectionsBySeverityFromEvents(dets)
	for _, k := range []string{"info", "low", "medium", "high"} {
		if _, ok := sevCounts[k]; !ok {
			sevCounts[k] = 0
		}
	}
	total := len(dets)
	dur := "running"
	if runStartTS > 0 && runEndTS > 0 && runEndTS >= runStartTS {
		dur = cliui.FormatDuration(runStartTS, runEndTS)
	}
	fmt.Fprintf(os.Stdout, "Run %s  dur=%s  detections=%d (info=%d low=%d med=%d high=%d)  cmd=%q\n\n",
		runID, dur, total, sevCounts["info"], sevCounts["low"], sevCounts["medium"], sevCounts["high"], cliui.Truncate(command, 80))
	fmt.Fprintln(os.Stdout, "Detections (grouped)")
	groups := groupDetectionsFromEvents(dets, limit)
	if len(groups) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
		return nil
	}
	bySeq := map[int64]storage.Event{}
	for _, ev := range allEvents {
		bySeq[ev.Seq] = ev
	}
	rows := make([][]string, 0, len(groups))
	for _, g := range groups {
		sample := "-"
		if g.SampleRelatedSeq > 0 {
			if ev, ok := bySeq[g.SampleRelatedSeq]; ok {
				sample = fmt.Sprintf("seq=%d %s", g.SampleRelatedSeq, evidenceFromEvent(ev, 40))
			} else {
				sample = fmt.Sprintf("seq=%d", g.SampleRelatedSeq)
			}
		}
		sev := g.Severity
		if clr.Enabled {
			sev = clr.Severity(g.Severity)
		}
		rows = append(rows, []string{
			sev,
			cliui.Truncate(g.RuleID, 12),
			fmt.Sprintf("%d", g.Count),
			cliui.Truncate(g.Message, 48),
			cliui.FormatTimestamp(g.FirstTS, runStartTS, tsMode),
			cliui.FormatTimestamp(g.LastTS, runStartTS, tsMode),
			cliui.Truncate(sample, 44),
		})
	}
	cliui.RenderTable(os.Stdout, []cliui.Column{
		{Name: "sev", MaxWidth: 6},
		{Name: "rule", MaxWidth: 12},
		{Name: "count", MaxWidth: 5, AlignRight: true},
		{Name: "message", MaxWidth: 48},
		{Name: "first", MaxWidth: 18},
		{Name: "last", MaxWidth: 18},
		{Name: "sample_related", MaxWidth: 44},
	}, rows)
	return nil
}

func explainShowRelatedFallback(runID string, allEvents []storage.Event, runStartTS, runEndTS int64, command string, limit int, all bool, tsMode cliui.TSMode, clr cliui.Colorizer) error {
	dets := storage.Filter(allEvents, storage.QueryOptions{RunID: runID, Type: storage.TypeDetection, Limit: limit})
	if all {
		dets = storage.Filter(allEvents, storage.QueryOptions{RunID: runID, Type: storage.TypeDetection})
	}
	bySeq := map[int64]storage.Event{}
	for _, ev := range allEvents {
		bySeq[ev.Seq] = ev
	}
	dur := "running"
	if runStartTS > 0 && runEndTS > 0 && runEndTS >= runStartTS {
		dur = cliui.FormatDuration(runStartTS, runEndTS)
	}
	fmt.Fprintf(os.Stdout, "Run %s  dur=%s  detections=%d  cmd=%q\n\n", runID, dur, len(dets), cliui.Truncate(command, 80))
	fmt.Fprintln(os.Stdout, "Detections (with related evidence)")
	if len(dets) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
		return nil
	}
	maxEvidence := 56
	if all {
		maxEvidence = 100000
	}
	rows := make([][]string, 0, len(dets))
	sort.Slice(dets, func(i, j int) bool {
		if dets[i].TS == dets[j].TS {
			return dets[i].Seq < dets[j].Seq
		}
		return dets[i].TS < dets[j].TS
	})
	for _, detEv := range dets {
		var d storage.Detection
		if err := json.Unmarshal(detEv.DataJSON, &d); err != nil {
			continue
		}
		evType := "-"
		evPID := "-"
		evidence := "-"
		if ev, ok := bySeq[d.RelatedEventSeq]; ok {
			evType = string(ev.Type)
			evPID = fmt.Sprintf("%d", ev.PID)
			evidence = evidenceFromEvent(ev, maxEvidence)
		}
		sev := d.Severity
		if clr.Enabled {
			sev = clr.Severity(d.Severity)
		}
		rows = append(rows, []string{
			sev,
			cliui.Truncate(d.RuleID, 10),
			fmt.Sprintf("%d", detEv.Seq),
			cliui.FormatTimestamp(detEv.TS, runStartTS, tsMode),
			fmt.Sprintf("%d", d.RelatedEventSeq),
			evType,
			evPID,
			evidence,
		})
	}
	cliui.RenderTable(os.Stdout, []cliui.Column{
		{Name: "sev", MaxWidth: 6},
		{Name: "rule", MaxWidth: 10},
		{Name: "det_seq", MaxWidth: 7, AlignRight: true},
		{Name: "at", MaxWidth: 18},
		{Name: "related_seq", MaxWidth: 11, AlignRight: true},
		{Name: "type", MaxWidth: 10},
		{Name: "pid", MaxWidth: 6, AlignRight: true},
		{Name: "evidence", MaxWidth: maxEvidence},
	}, rows)
	return nil
}

func explainDrillFallback(runID string, seq int64, allEvents []storage.Event, runStartTS int64) error {
	var detEv storage.Event
	found := false
	for _, ev := range allEvents {
		if ev.Type == storage.TypeDetection && ev.Seq == seq {
			detEv = ev
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("detection seq=%d not found in run %s", seq, runID)
	}
	var det storage.Detection
	if err := json.Unmarshal(detEv.DataJSON, &det); err != nil {
		return fmt.Errorf("decode detection seq=%d: %w", seq, err)
	}
	fmt.Fprintf(os.Stdout, "Run %s\n", runID)
	fmt.Fprintf(os.Stdout, "Detection\n")
	fmt.Fprintf(os.Stdout, "  seq=%d ts=%s sev=%s rule=%s related_seq=%d\n", detEv.Seq, cliui.FormatAbsFull(detEv.TS), det.Severity, det.RuleID, det.RelatedEventSeq)
	fmt.Fprintf(os.Stdout, "  message=%s\n\n", det.Message)
	if det.RelatedEventSeq <= 0 {
		fmt.Fprintln(os.Stdout, "Related event: (none)")
		return nil
	}
	for _, ev := range allEvents {
		if ev.Seq != det.RelatedEventSeq {
			continue
		}
		fmt.Fprintf(os.Stdout, "Related event\n")
		fmt.Fprintf(os.Stdout, "  seq=%d ts=%s rel=%s type=%s pid=%d\n", ev.Seq, cliui.FormatAbsFull(ev.TS), cliui.FormatRel(ev.TS, runStartTS), ev.Type, ev.PID)
		fmt.Fprintf(os.Stdout, "  summary=%s\n", ev.Summary)
		fmt.Fprintf(os.Stdout, "  evidence=%s\n", evidenceFromEvent(ev, 100000))
		return nil
	}
	fmt.Fprintf(os.Stdout, "Related event seq=%d not found\n", det.RelatedEventSeq)
	return nil
}

func explainLegacy(runID, runDir string, meta runs.Meta, asJSON bool) error {
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

func explainUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s explain: explain detections for a run\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s explain [flags] [last|<run-id>]\n\n", prog)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s explain last\n", prog)
	fmt.Fprintf(w, "  %s explain last --show-related\n", prog)
	fmt.Fprintf(w, "  %s explain last --drill 35\n", prog)
	fmt.Fprintf(w, "  %s explain last --raw\n", prog)
	fmt.Fprintf(w, "  %s explain --json last\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
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
		ts := cliui.FormatAbsFull(ev.TS)
		fmt.Fprintf(&b, "- %s %s sev=%s related_seq=%d: %s\n", ts, det.RuleID, det.Severity, det.RelatedEventSeq, det.Message)
	}
	return b.String()
}
