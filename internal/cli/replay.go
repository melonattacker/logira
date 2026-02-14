package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/melonattacker/logira/internal/logging"
	"github.com/melonattacker/logira/internal/storage"
)

// ReplayCommand is deprecated. Use `logira query`.
func ReplayCommand(ctx context.Context, args []string) error {
	fs := newFlagSet("replay", args, replayUsage)

	var logPath string
	var pretty bool
	fs.StringVar(&logPath, "log", "", "deprecated: run directory or run id")
	fs.BoolVar(&pretty, "pretty", false, "deprecated; pretty-print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "warning: 'replay' is deprecated; use 'query' instead")

	sel := "last"
	if strings.TrimSpace(logPath) != "" {
		if fi, err := os.Stat(logPath); err == nil {
			if fi.IsDir() {
				// New-style run directory.
				p := filepath.Join(logPath, "events.jsonl")
				if _, err := os.Stat(p); err == nil {
					return replayJSONLFile(p, pretty)
				}
				// Legacy dir of log files.
				paths, err := logging.CollectLogFiles(logPath)
				if err != nil {
					return err
				}
				evs, err := logging.ReadEvents(paths)
				if err != nil {
					return err
				}
				enc := json.NewEncoder(os.Stdout)
				if pretty {
					enc.SetIndent("", "  ")
				}
				for _, ev := range evs {
					if err := enc.Encode(ev); err != nil {
						return err
					}
				}
				return nil
			}
			return replayJSONLFile(logPath, pretty)
		}

		if strings.Contains(logPath, string(os.PathSeparator)) {
			sel = filepath.Base(filepath.Clean(logPath))
		} else {
			sel = strings.TrimSpace(logPath)
		}
	}

	return QueryCommand(ctx, []string{"--run", sel})
}

func replayJSONLFile(path string, pretty bool) error {
	if evs, err := storage.ReadJSONL(path); err == nil {
		enc := json.NewEncoder(os.Stdout)
		if pretty {
			enc.SetIndent("", "  ")
		}
		for _, ev := range evs {
			if err := enc.Encode(ev); err != nil {
				return err
			}
		}
		return nil
	}

	evs, err := logging.ReadEvents([]string{path})
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	if pretty {
		enc.SetIndent("", "  ")
	}
	for _, ev := range evs {
		if err := enc.Encode(ev); err != nil {
			return err
		}
	}
	return nil
}

func replayUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s replay: (deprecated) backward wrapper for '%s query'\n\n", prog, prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s replay [--pretty] [--log <file|dir|run-id>]\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  This command is deprecated; use 'query' instead.")
	fmt.Fprintln(w, "  --log accepts a v2 run directory/id, or a legacy log file/dir.")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s replay --log last\n", prog)
	fmt.Fprintf(w, "  %s replay --log ~/.logira/runs/<run-id>/\n", prog)
	fmt.Fprintf(w, "  %s replay --log ./events.jsonl --pretty\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
