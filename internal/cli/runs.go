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

	"github.com/melonattacker/logira/internal/runs"
)

func RunsCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := flag.NewFlagSet("runs", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	base := filepath.Join(home, "runs")
	ents, err := os.ReadDir(base)
	if err != nil {
		return err
	}

	type row struct {
		RunID           string `json:"run_id"`
		StartTS         int64  `json:"start_ts"`
		EndTS           int64  `json:"end_ts"`
		Tool            string `json:"tool"`
		Command         string `json:"command"`
		SuspiciousCount int    `json:"suspicious_count"`
	}

	rows := make([]row, 0, len(ents))
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(base, e.Name())
		m, err := runs.ReadMeta(dir)
		if err != nil {
			continue
		}
		rows = append(rows, row{
			RunID:           m.RunID,
			StartTS:         m.StartTS,
			EndTS:           m.EndTS,
			Tool:            m.Tool,
			Command:         m.Command,
			SuspiciousCount: m.SuspiciousCount,
		})
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].StartTS == rows[j].StartTS {
			return rows[i].RunID < rows[j].RunID
		}
		return rows[i].StartTS < rows[j].StartTS
	})

	if asJSON {
		return json.NewEncoder(os.Stdout).Encode(rows)
	}

	if len(rows) == 0 {
		fmt.Fprintln(os.Stdout, "(no runs)")
		return nil
	}

	for _, r := range rows {
		start := time.Unix(0, r.StartTS).UTC().Format(time.RFC3339)
		end := ""
		if r.EndTS > 0 {
			end = time.Unix(0, r.EndTS).UTC().Format(time.RFC3339)
		}
		cmd := strings.TrimSpace(r.Command)
		if cmd == "" {
			cmd = "<unknown>"
		}
		fmt.Fprintf(os.Stdout, "%s  start=%s  end=%s  suspicious=%d  tool=%s  cmd=%s\n",
			r.RunID, start, end, r.SuspiciousCount, r.Tool, cmd)
	}
	return nil
}
