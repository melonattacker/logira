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
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func ViewCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("view", args, viewUsage)

	var (
		asJSON  bool
		raw     bool
		noColor bool
		colorS  string
		limit   int
		tsModeS string
	)
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.BoolVar(&raw, "raw", false, "emit legacy text output")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&colorS, "color", "auto", "color mode: auto|always|never")
	fs.IntVar(&limit, "limit", 10, "max grouped detections")
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
		return viewLegacy(runID, runDir, meta, asJSON)
	}

	clr := cliui.NewColorizer(colorMode, noColor, os.Stdout)
	var (
		runStartTS = meta.StartTS
		runEndTS   = meta.EndTS
		tool       = strings.TrimSpace(meta.Tool)
		command    = strings.TrimSpace(meta.Command)
	)
	eventCounts := map[storage.EventType]int{}
	sevCounts := map[string]int{"info": 0, "low": 0, "medium": 0, "high": 0}
	groups := make([]groupedDetection, 0, limit)

	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()

		if runRow, err := sqlite.GetRunRow(runID); err == nil {
			if runStartTS == 0 {
				runStartTS = runRow.StartTS
			}
			if runEndTS == 0 {
				runEndTS = runRow.EndTS
			}
			if tool == "" {
				tool = strings.TrimSpace(runRow.Tool)
			}
			if command == "" {
				command = strings.TrimSpace(runRow.Command)
			}
		}
		if c, err := sqlite.CountEventsByType(runID); err == nil {
			for k, v := range c {
				eventCounts[k] = v
			}
		}
		if c, err := sqlite.CountDetectionsBySeverity(runID); err == nil {
			for k := range sevCounts {
				sevCounts[k] = c[k]
			}
		}
		if gs, err := sqlite.ListGroupedDetections(runID, limit); err == nil {
			groups = groups[:0]
			for _, g := range gs {
				groups = append(groups, groupedDetection{
					Severity:         g.Severity,
					RuleID:           g.RuleID,
					Message:          g.Message,
					Count:            g.Count,
					FirstTS:          g.FirstTS,
					LastTS:           g.LastTS,
					SampleRelatedSeq: g.SampleRelatedSeq,
				})
			}
		}
	} else {
		all, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
		if rerr != nil {
			return fmt.Errorf("open sqlite: %v; read events.jsonl: %w", err, rerr)
		}
		all = storage.Filter(all, storage.QueryOptions{RunID: runID})
		for _, ev := range all {
			eventCounts[ev.Type]++
			if ev.Type == storage.TypeDetection {
				var d storage.Detection
				if err := json.Unmarshal(ev.DataJSON, &d); err == nil {
					sevCounts[d.Severity]++
				}
			}
		}
		if len(groups) == 0 {
			groups = groupDetectionsFromEvents(all, limit)
		}
	}

	if tool == "" {
		tool = "-"
	}
	if command == "" {
		command = "-"
	}
	dur := "running"
	if runStartTS > 0 && runEndTS > 0 && runEndTS >= runStartTS {
		dur = cliui.FormatDuration(runStartTS, runEndTS)
	}
	fmt.Fprintf(os.Stdout, "Run %s  tool=%s  dur=%s  cmd=%q\n", runID, tool, dur, cliui.Truncate(command, 96))
	fmt.Fprintf(os.Stdout, "Window %s .. %s\n\n", cliui.FormatAbsShort(runStartTS), cliui.FormatAbsShort(runEndTS))

	detTotal := sevCounts["info"] + sevCounts["low"] + sevCounts["medium"] + sevCounts["high"]
	execCount := eventCounts[storage.TypeExec]
	fileCount := eventCounts[storage.TypeFile]
	netCount := eventCounts[storage.TypeNet]
	detectionWord := clr.Type("detections")
	fmt.Fprintf(
		os.Stdout,
		"Counts   exec=%d  file=%d  net=%d  %s=%d (info=%d low=%d med=%d high=%d)\n\n",
		execCount, fileCount, netCount, detectionWord, detTotal,
		sevCounts["info"], sevCounts["low"], sevCounts["medium"], sevCounts["high"],
	)

	fmt.Fprintln(os.Stdout, "Top detections (grouped)")
	if len(groups) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
	} else {
		rows := make([][]string, 0, len(groups))
		for _, g := range groups {
			sev := g.Severity
			if clr.Enabled {
				sev = clr.Severity(g.Severity)
			}
			extra := fmt.Sprintf(
				"first=%s last=%s",
				cliui.FormatTimestamp(g.FirstTS, runStartTS, tsMode),
				cliui.FormatTimestamp(g.LastTS, runStartTS, tsMode),
			)
			if g.SampleRelatedSeq > 0 {
				extra += fmt.Sprintf(" sample=%d", g.SampleRelatedSeq)
			}
			rows = append(rows, []string{
				sev,
				cliui.Truncate(g.RuleID, 12),
				fmt.Sprintf("%d", g.Count),
				cliui.Truncate(g.Message, 52),
				cliui.Truncate(extra, 48),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "sev", MaxWidth: 6},
			{Name: "rule", MaxWidth: 12},
			{Name: "count", MaxWidth: 5, AlignRight: true},
			{Name: "message", MaxWidth: 52},
			{Name: "extra", MaxWidth: 48},
		}, rows)
	}

	fmt.Fprintln(os.Stdout, "\nHints:")
	fmt.Fprintf(os.Stdout, "- %s explain %s --show-related\n", progName(), runID)
	fmt.Fprintf(os.Stdout, "- %s query %s --type net --limit 20\n", progName(), runID)
	return nil
}

func viewLegacy(runID, runDir string, meta runs.Meta, asJSON bool) error {
	var (
		timeline []storage.Event
		dets     []storage.Event

		topExec  []storage.TopPair
		topPaths []storage.TopPair
		topDest  []storage.TopPair
		fileOps  []storage.TopPair
	)

	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()

		timeline, err = sqlite.Query(storage.QueryOptions{RunID: runID, Limit: 500})
		if err != nil {
			return err
		}
		dets, err = sqlite.Query(storage.QueryOptions{RunID: runID, Type: storage.TypeDetection, Limit: 500})
		if err != nil {
			return err
		}

		topExec, _ = sqlite.TopExec(runID, 20)
		topPaths, _ = sqlite.TopPaths(runID, 20)
		topDest, _ = sqlite.TopDestinations(runID, 20)
		fileOps, _ = computeFileOps(sqlite.DB, runID, 20)
	} else {
		all, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
		if rerr != nil {
			return fmt.Errorf("open sqlite: %v; read events.jsonl: %w", err, rerr)
		}
		all = storage.Filter(all, storage.QueryOptions{RunID: runID})
		timeline = all
		if len(timeline) > 500 {
			timeline = timeline[:500]
		}
		dets = storage.Filter(all, storage.QueryOptions{RunID: runID, Type: storage.TypeDetection, Limit: 500})
		topExec = topExecFromEvents(all, 20)
		topPaths = topPathsFromEvents(all, 20)
		topDest = topDestinationsFromEvents(all, 20)
		fileOps = fileOpsFromEvents(all, 20)
	}

	sort.Slice(dets, func(i, j int) bool {
		// severity desc, then ts
		si := severityRank(dets[i])
		sj := severityRank(dets[j])
		if si == sj {
			if dets[i].TS == dets[j].TS {
				return dets[i].Seq < dets[j].Seq
			}
			return dets[i].TS < dets[j].TS
		}
		return si > sj
	})

	out := struct {
		Meta         runs.Meta         `json:"meta"`
		Timeline     []storage.Event   `json:"timeline"`
		Detections   []storage.Event   `json:"detections"`
		TopCommands  []storage.TopPair `json:"top_commands"`
		FileOps      []storage.TopPair `json:"file_ops"`
		ChangedFiles []storage.TopPair `json:"changed_files"`
		Destinations []storage.TopPair `json:"destinations"`
	}{
		Meta:         meta,
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

	fmt.Fprintf(os.Stdout, "Run: %s\n", runID)
	if meta.StartTS > 0 {
		fmt.Fprintf(os.Stdout, "Start: %s\n", time.Unix(0, meta.StartTS).UTC().Format(time.RFC3339))
	}
	if meta.EndTS > 0 {
		fmt.Fprintf(os.Stdout, "End:   %s\n", time.Unix(0, meta.EndTS).UTC().Format(time.RFC3339))
	}
	if strings.TrimSpace(meta.Command) != "" {
		fmt.Fprintf(os.Stdout, "Cmd:   %s\n", meta.Command)
	}
	fmt.Fprintf(os.Stdout, "Suspicious: %d\n", meta.SuspiciousCount)

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

func viewUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s view: view a run summary\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s view [flags] [last|<run-id>]\n\n", prog)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s view\n", prog)
	fmt.Fprintf(w, "  %s view last --limit 5\n", prog)
	fmt.Fprintf(w, "  %s view --ts both --no-color last\n", prog)
	fmt.Fprintf(w, "  %s view --raw last\n", prog)
	fmt.Fprintf(w, "  %s view --json last\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}

func severityRank(ev storage.Event) int {
	if ev.Type != storage.TypeDetection {
		return 0
	}
	var det storage.Detection
	if err := json.Unmarshal(ev.DataJSON, &det); err != nil {
		return 0
	}
	return severityWeight(det.Severity)
}

func printTopPairs(title string, ps []storage.TopPair) {
	fmt.Fprintf(os.Stdout, "\n%s:\n", title)
	if len(ps) == 0 {
		fmt.Fprintln(os.Stdout, "(none)")
		return
	}
	for _, p := range ps {
		fmt.Fprintf(os.Stdout, "  %5d  %s\n", p.Count, p.Key)
	}
}

func computeFileOps(db *sql.DB, runID string, n int) ([]storage.TopPair, error) {
	rows, err := db.Query(`SELECT data_json FROM events WHERE run_id=? AND type='file'`, runID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var d model.FileDetail
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			continue
		}
		op := strings.TrimSpace(d.Op)
		if op == "" {
			op = "unknown"
		}
		counts[op]++
	}
	out := make([]storage.TopPair, 0, len(counts))
	for k, v := range counts {
		out = append(out, storage.TopPair{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n <= 0 {
		n = 20
	}
	if len(out) > n {
		out = out[:n]
	}
	return out, rows.Err()
}

func fileOpsFromEvents(evs []storage.Event, n int) []storage.TopPair {
	counts := map[string]int{}
	for _, ev := range evs {
		if ev.Type != storage.TypeFile {
			continue
		}
		var d model.FileDetail
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		op := strings.TrimSpace(d.Op)
		if op == "" {
			op = "unknown"
		}
		counts[op]++
	}
	return topPairsFromCounts(counts, n)
}

func topExecFromEvents(evs []storage.Event, n int) []storage.TopPair {
	counts := map[string]int{}
	for _, ev := range evs {
		if ev.Type != storage.TypeExec {
			continue
		}
		var d model.ExecDetail
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		key := strings.TrimSpace(d.Filename)
		if key == "" && len(d.Argv) > 0 {
			key = strings.TrimSpace(d.Argv[0])
		}
		if key == "" {
			key = "<unknown>"
		}
		counts[key]++
	}
	return topPairsFromCounts(counts, n)
}

func topPathsFromEvents(evs []storage.Event, n int) []storage.TopPair {
	counts := map[string]int{}
	for _, ev := range evs {
		if ev.Type != storage.TypeFile {
			continue
		}
		var d model.FileDetail
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		p := strings.TrimSpace(d.Path)
		if p == "" {
			p = "<unknown>"
		}
		counts[p]++
	}
	return topPairsFromCounts(counts, n)
}

func topDestinationsFromEvents(evs []storage.Event, n int) []storage.TopPair {
	counts := map[string]int{}
	for _, ev := range evs {
		if ev.Type != storage.TypeNet {
			continue
		}
		var d model.NetDetail
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		ip := strings.TrimSpace(d.DstIP)
		if ip == "" {
			ip = "unknown"
		}
		key := ip
		if d.DstPort != 0 {
			key = fmt.Sprintf("%s:%d", ip, d.DstPort)
		}
		counts[key]++
	}
	return topPairsFromCounts(counts, n)
}

func topPairsFromCounts(counts map[string]int, n int) []storage.TopPair {
	out := make([]storage.TopPair, 0, len(counts))
	for k, v := range counts {
		out = append(out, storage.TopPair{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if n <= 0 {
		n = 20
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}
