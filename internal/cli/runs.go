package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/runs"
)

func RunsCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("runs", args, runsUsage)

	var (
		asJSON  bool
		noColor bool
		colorS  string
	)
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&colorS, "color", "auto", "color mode: auto|always|never")
	if err := fs.Parse(args); err != nil {
		return err
	}
	colorMode, err := cliui.ParseColorMode(colorS)
	if err != nil {
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

	clr := cliui.NewColorizer(colorMode, noColor, os.Stdout)

	tableRows := make([][]string, 0, len(rows))
	for _, r := range rows {
		started := cliui.FormatDateTimeShort(r.StartTS)
		dur := "-"
		if r.StartTS > 0 && r.EndTS > 0 && r.EndTS >= r.StartTS {
			dur = cliui.FormatDuration(r.StartTS, r.EndTS)
		}
		cmd := strings.TrimSpace(r.Command)
		if cmd == "" {
			cmd = "<unknown>"
		}
		detStr := fmt.Sprintf("%d", r.SuspiciousCount)
		if r.SuspiciousCount > 0 {
			detStr = clr.Warn(detStr)
		}
		tableRows = append(tableRows, []string{
			r.RunID,
			started,
			dur,
			cliui.Truncate(cmd, 40),
			detStr,
		})
	}

	cliui.RenderTable(os.Stdout, []cliui.Column{
		{Name: "run_id", MaxWidth: 20},
		{Name: "started", MaxWidth: 18},
		{Name: "dur", MaxWidth: 10, AlignRight: true},
		{Name: "cmd", MaxWidth: 40},
		{Name: "detections", MaxWidth: 10, AlignRight: true},
	}, tableRows)
	return nil
}

func runsUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s runs: list saved runs\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s runs [--json] [--no-color] [--color auto|always|never]\n\n", prog)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s runs\n", prog)
	fmt.Fprintf(w, "  %s runs --json\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
