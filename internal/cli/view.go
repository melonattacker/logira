package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/melonattacker/agentlogix/internal/model"
	"github.com/melonattacker/agentlogix/internal/runs"
	"github.com/melonattacker/agentlogix/internal/storage"
)

func ViewCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := flag.NewFlagSet("view", flag.ContinueOnError)
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

func severityRank(ev storage.Event) int {
	if ev.Type != storage.TypeDetection {
		return 0
	}
	var det storage.Detection
	if err := json.Unmarshal(ev.DataJSON, &det); err != nil {
		return 0
	}
	switch det.Severity {
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
