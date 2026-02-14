package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/melonattacker/logira/internal/logging"
	"github.com/melonattacker/logira/internal/storage"
)

// ReplayCommand is deprecated. Use `logira query`.
func ReplayCommand(ctx context.Context, args []string) error {
	fmt.Fprintln(os.Stderr, "warning: 'replay' is deprecated; use 'query' instead")

	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var logPath string
	var pretty bool
	fs.StringVar(&logPath, "log", "", "deprecated: run directory or run id")
	fs.BoolVar(&pretty, "pretty", false, "deprecated; pretty-print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

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
