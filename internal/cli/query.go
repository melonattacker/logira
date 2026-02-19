package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func QueryCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("query", args, queryUsage)

	var runSel string
	var typ string
	var since string
	var contains string
	var path string
	var dest string
	var severity string
	var asJSON bool
	var all bool
	var noColor bool
	var colorS string
	var relatedToDetections bool
	var tsModeS string
	var limit int

	runSel = "last"
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		runSel = args[0]
		parseArgs = args[1:]
	}

	fs.StringVar(&runSel, "run", runSel, "run id or 'last'")
	fs.StringVar(&typ, "type", "all", "exec|file|net|detection|all")
	fs.StringVar(&since, "since", "", "duration like 1h, 24h, -10s")
	fs.StringVar(&contains, "contains", "", "substring match in summary/data")
	fs.StringVar(&path, "path", "", "path substring (file events)")
	fs.StringVar(&dest, "dest", "", "destination ip:port (net events)")
	fs.StringVar(&severity, "severity", "", "detection severity (info|low|medium|high)")
	fs.BoolVar(&relatedToDetections, "related-to-detections", false, "show only events referenced by detections.related_seq")
	fs.BoolVar(&asJSON, "json", false, "emit JSONL events")
	fs.BoolVar(&all, "all", false, "disable truncation and limits")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&colorS, "color", "auto", "color mode: auto|always|never")
	fs.StringVar(&tsModeS, "ts", "rel", "timestamp mode: abs|rel|both")
	fs.IntVar(&limit, "limit", 20, "max results")
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if fs.NArg() > 0 && runSel == "last" {
		runSel = fs.Arg(0)
	}
	if all {
		limit = 100000
	}
	if limit <= 0 {
		limit = 20
	}
	tsMode, err := cliui.ParseTSMode(tsModeS)
	if err != nil {
		return err
	}
	colorMode, err := cliui.ParseColorMode(colorS)
	if err != nil {
		return err
	}

	eventType, err := parseEventType(typ)
	if err != nil {
		return err
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	runID, runDir, err := runs.ResolveRunID(home, runSel)
	if err != nil {
		return err
	}

	var sinceTS int64
	if strings.TrimSpace(since) != "" {
		d, err := time.ParseDuration(since)
		if err != nil {
			return fmt.Errorf("parse --since: %w", err)
		}
		now := time.Now().UTC()
		if d < 0 {
			sinceTS = now.Add(d).UnixNano()
		} else {
			sinceTS = now.Add(-d).UnixNano()
		}
	}

	var dstIP string
	var dstPort int
	if strings.TrimSpace(dest) != "" {
		ip, port, err := parseDest(dest)
		if err != nil {
			return err
		}
		dstIP, dstPort = ip, port
	}

	opts := storage.QueryOptions{
		RunID:               runID,
		Type:                eventType,
		SinceTS:             sinceTS,
		Contains:            contains,
		Path:                path,
		DstIP:               dstIP,
		DstPort:             dstPort,
		Severity:            severity,
		RelatedToDetections: relatedToDetections && eventType != storage.TypeDetection,
		Limit:               limit,
	}

	var (
		evs        []storage.Event
		runStartTS int64
	)
	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()
		if rr, err := sqlite.GetRunRow(runID); err == nil {
			runStartTS = rr.StartTS
		}
		if opts.RelatedToDetections {
			evs, err = sqlite.QueryObservedRelatedToDetections(opts)
		} else {
			evs, err = sqlite.Query(opts)
		}
		if err != nil {
			return err
		}
	} else {
		allEvents, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
		if rerr != nil {
			return fmt.Errorf("open sqlite: %v; read events.jsonl: %w", err, rerr)
		}
		meta, _ := runs.ReadMeta(runDir)
		runStartTS = meta.StartTS
		evs = storage.Filter(allEvents, opts)
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, ev := range evs {
			if err := enc.Encode(ev); err != nil {
				return err
			}
		}
		return nil
	}

	clr := cliui.NewColorizer(colorMode, noColor, os.Stdout)
	return printQueryTable(evs, eventType, runStartTS, tsMode, all, clr)
}

func printQueryTable(evs []storage.Event, eventType storage.EventType, runStartTS int64, tsMode cliui.TSMode, all bool, clr cliui.Colorizer) error {
	if len(evs) == 0 {
		fmt.Fprintln(os.Stdout, "(no events)")
		return nil
	}

	switch eventType {
	case storage.TypeExec:
		rows := make([][]string, 0, len(evs))
		maxArg := 56
		if all {
			maxArg = 100000
		}
		for _, ev := range evs {
			d, _ := parseExecDetail(ev.DataJSON)
			exe := strings.TrimSpace(d.Filename)
			if exe == "" && len(d.Argv) > 0 {
				exe = d.Argv[0]
			}
			argv := "-"
			if len(d.Argv) > 0 {
				argv = strings.Join(d.Argv, " ")
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", ev.Seq),
				cliui.FormatTimestamp(ev.TS, runStartTS, tsMode),
				fmt.Sprintf("%d", ev.PID),
				fmt.Sprintf("%d", ev.UID),
				cliui.Truncate(exe, 32),
				cliui.Truncate(d.CWD, 28),
				cliui.Truncate(argv, maxArg),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "seq", MaxWidth: 6, AlignRight: true},
			{Name: "at", MaxWidth: 18},
			{Name: "pid", MaxWidth: 6, AlignRight: true},
			{Name: "uid", MaxWidth: 6, AlignRight: true},
			{Name: "exe", MaxWidth: 32},
			{Name: "cwd", MaxWidth: 28},
			{Name: "argv", MaxWidth: maxArg},
		}, rows)
		return nil
	case storage.TypeFile:
		rows := make([][]string, 0, len(evs))
		for _, ev := range evs {
			d, _ := parseFileDetail(ev.DataJSON)
			before := "-"
			after := "-"
			if d.SizeBefore != nil {
				before = fmt.Sprintf("%d", *d.SizeBefore)
			}
			if d.SizeAfter != nil {
				after = fmt.Sprintf("%d", *d.SizeAfter)
			}
			hash := strings.TrimSpace(d.HashAfter)
			if hash == "" {
				hash = "-"
			}
			if d.HashTruncated {
				hash += " (trunc)"
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", ev.Seq),
				cliui.FormatTimestamp(ev.TS, runStartTS, tsMode),
				fmt.Sprintf("%d", ev.PID),
				cliui.Truncate(d.Op, 10),
				cliui.Truncate(d.Path, 48),
				before,
				after,
				cliui.Truncate(hash, 24),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "seq", MaxWidth: 6, AlignRight: true},
			{Name: "at", MaxWidth: 18},
			{Name: "pid", MaxWidth: 6, AlignRight: true},
			{Name: "op", MaxWidth: 10},
			{Name: "path", MaxWidth: 48},
			{Name: "size_before", MaxWidth: 11, AlignRight: true},
			{Name: "size_after", MaxWidth: 10, AlignRight: true},
			{Name: "hash_after", MaxWidth: 24},
		}, rows)
		return nil
	case storage.TypeNet:
		rows := make([][]string, 0, len(evs))
		for _, ev := range evs {
			d, _ := parseNetDetail(ev.DataJSON)
			dst := strings.TrimSpace(d.DstIP)
			if d.DstPort > 0 {
				dst = fmt.Sprintf("%s:%d", d.DstIP, d.DstPort)
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", ev.Seq),
				cliui.FormatTimestamp(ev.TS, runStartTS, tsMode),
				fmt.Sprintf("%d", ev.PID),
				cliui.Truncate(d.Op, 10),
				cliui.Truncate(d.Proto, 8),
				cliui.Truncate(dst, 28),
				fmt.Sprintf("%d", d.Bytes),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "seq", MaxWidth: 6, AlignRight: true},
			{Name: "at", MaxWidth: 18},
			{Name: "pid", MaxWidth: 6, AlignRight: true},
			{Name: "op", MaxWidth: 10},
			{Name: "proto", MaxWidth: 8},
			{Name: "dst", MaxWidth: 28},
			{Name: "bytes", MaxWidth: 10, AlignRight: true},
		}, rows)
		return nil
	case storage.TypeDetection:
		rows := make([][]string, 0, len(evs))
		for _, ev := range evs {
			var d storage.Detection
			_ = json.Unmarshal(ev.DataJSON, &d)
			sev := d.Severity
			if clr.Enabled {
				sev = clr.Severity(d.Severity)
			}
			rows = append(rows, []string{
				fmt.Sprintf("%d", ev.Seq),
				cliui.FormatTimestamp(ev.TS, runStartTS, tsMode),
				sev,
				cliui.Truncate(d.RuleID, 10),
				cliui.Truncate(d.Message, 64),
				fmt.Sprintf("%d", d.RelatedEventSeq),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "seq", MaxWidth: 6, AlignRight: true},
			{Name: "at", MaxWidth: 18},
			{Name: "sev", MaxWidth: 6},
			{Name: "rule", MaxWidth: 10},
			{Name: "message", MaxWidth: 64},
			{Name: "related_seq", MaxWidth: 11, AlignRight: true},
		}, rows)
		return nil
	default:
		rows := make([][]string, 0, len(evs))
		for _, ev := range evs {
			rows = append(rows, []string{
				fmt.Sprintf("%d", ev.Seq),
				cliui.FormatTimestamp(ev.TS, runStartTS, tsMode),
				clr.Type(string(ev.Type)),
				fmt.Sprintf("%d", ev.PID),
				cliui.Truncate(ev.Summary, 80),
			})
		}
		cliui.RenderTable(os.Stdout, []cliui.Column{
			{Name: "seq", MaxWidth: 6, AlignRight: true},
			{Name: "at", MaxWidth: 18},
			{Name: "type", MaxWidth: 10},
			{Name: "pid", MaxWidth: 6, AlignRight: true},
			{Name: "summary", MaxWidth: 80},
		}, rows)
		return nil
	}
}

func parseEventType(v string) (storage.EventType, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "all":
		return "", nil
	case "exec":
		return storage.TypeExec, nil
	case "file":
		return storage.TypeFile, nil
	case "net":
		return storage.TypeNet, nil
	case "detection":
		return storage.TypeDetection, nil
	default:
		return "", fmt.Errorf("invalid --type %q (expected exec|file|net|detection|all)", v)
	}
}

func parseDest(s string) (ip string, port int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, fmt.Errorf("empty dest")
	}
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		// allow ip only
		if net.ParseIP(s) != nil {
			return s, 0, nil
		}
		return "", 0, fmt.Errorf("invalid --dest %q (expected ip:port): %w", s, err)
	}
	if net.ParseIP(host) == nil {
		return "", 0, fmt.Errorf("invalid dest ip %q", host)
	}
	pi, err := strconv.Atoi(p)
	if err != nil {
		return "", 0, fmt.Errorf("invalid dest port %q", p)
	}
	return host, pi, nil
}

func queryUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s query: search events in a run\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s query [flags]\n", prog)
	fmt.Fprintf(w, "  %s query [last|<run-id>] [flags]\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  --run defaults to 'last'.")
	fmt.Fprintln(w, "  --since uses Go duration syntax (e.g. 10m, 24h, -10s).")
	fmt.Fprintln(w, "  --dest accepts ip or ip:port (e.g. 93.184.216.34:443).")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s query last --type net --limit 20\n", prog)
	fmt.Fprintf(w, "  %s query --type detection --severity high\n", prog)
	fmt.Fprintf(w, "  %s query --related-to-detections --type net\n", prog)
	fmt.Fprintf(w, "  %s query --json --run last --contains curl\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
