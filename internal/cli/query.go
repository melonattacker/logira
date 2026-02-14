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
	var limit int

	fs.StringVar(&runSel, "run", "last", "run id or 'last'")
	fs.StringVar(&typ, "type", "", "exec|file|net|detection")
	fs.StringVar(&since, "since", "", "duration like 1h, 24h")
	fs.StringVar(&contains, "contains", "", "substring match in summary/data")
	fs.StringVar(&path, "path", "", "path substring (file events)")
	fs.StringVar(&dest, "dest", "", "destination ip:port (net events)")
	fs.StringVar(&severity, "severity", "", "detection severity (info|low|medium|high)")
	fs.BoolVar(&asJSON, "json", false, "emit JSONL events")
	fs.IntVar(&limit, "limit", 5000, "max results")

	if err := fs.Parse(args); err != nil {
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
		sinceTS = time.Now().UTC().Add(-d).UnixNano()
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
		RunID:    runID,
		SinceTS:  sinceTS,
		Contains: contains,
		Path:     path,
		DstIP:    dstIP,
		DstPort:  dstPort,
		Severity: severity,
		Limit:    limit,
	}
	if strings.TrimSpace(typ) != "" {
		opts.Type = storage.EventType(strings.TrimSpace(typ))
	}

	var evs []storage.Event
	if sqlite, err := storage.OpenSQLiteReadOnly(filepath.Join(runDir, "index.sqlite")); err == nil {
		defer sqlite.Close()
		evs, err = sqlite.Query(opts)
		if err != nil {
			return err
		}
	} else {
		all, rerr := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
		if rerr != nil {
			return fmt.Errorf("open sqlite: %v; read events.jsonl: %w", err, rerr)
		}
		evs = storage.Filter(all, opts)
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

	for _, ev := range evs {
		ts := time.Unix(0, ev.TS).UTC().Format(time.RFC3339Nano)
		fmt.Fprintf(os.Stdout, "%s %s seq=%d pid=%d %s\n", ts, ev.Type, ev.Seq, ev.PID, ev.Summary)
	}
	return nil
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
	fmt.Fprintf(w, "  %s query [flags]\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  --run defaults to 'last'.")
	fmt.Fprintln(w, "  --since uses Go duration syntax (e.g. 10m, 24h).")
	fmt.Fprintln(w, "  --dest accepts ip or ip:port (e.g. 93.184.216.34:443).")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s query --type detection\n", prog)
	fmt.Fprintf(w, "  %s query --type net --dest 93.184.216.34:443\n", prog)
	fmt.Fprintf(w, "  %s query --since 1h --contains curl\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
