package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/melonattacker/agentlogix/internal/logging"
)

func ReplayCommand(ctx context.Context, args []string) error {
	_ = ctx

	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var logPath string
	var pretty bool
	fs.StringVar(&logPath, "log", "", "log file or directory")
	fs.BoolVar(&pretty, "pretty", false, "human-readable output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(logPath) == "" {
		return fmt.Errorf("--log is required")
	}

	files, err := logging.CollectLogFiles(logPath)
	if err != nil {
		return err
	}
	events, err := logging.ReadEvents(files)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(os.Stdout)
	for _, ev := range events {
		if !pretty {
			if err := enc.Encode(ev); err != nil {
				return err
			}
			continue
		}
		switch ev.Type {
		case "exec":
			d, _ := parseExecDetail(ev.Detail)
			fmt.Fprintf(os.Stdout, "%s exec pid=%d ppid=%d cmd=%s argv=%v cwd=%s\n", ev.Timestamp, ev.PID, ev.PPID, d.Filename, d.Argv, d.CWD)
		case "file":
			d, _ := parseFileDetail(ev.Detail)
			fmt.Fprintf(os.Stdout, "%s file pid=%d op=%s path=%s\n", ev.Timestamp, ev.PID, d.Op, d.Path)
		case "net":
			d, _ := parseNetDetail(ev.Detail)
			fmt.Fprintf(os.Stdout, "%s net pid=%d op=%s proto=%s dst=%s:%d bytes=%d\n", ev.Timestamp, ev.PID, d.Op, d.Proto, d.DstIP, d.DstPort, d.Bytes)
		default:
			fmt.Fprintf(os.Stdout, "%s unknown type=%s pid=%d\n", ev.Timestamp, ev.Type, ev.PID)
		}
	}
	return nil
}
