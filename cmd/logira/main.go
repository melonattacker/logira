package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/melonattacker/logira/internal/cli"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	prog := filepath.Base(os.Args[0])
	if len(os.Args) < 2 {
		printRootHelp(os.Stderr, prog)
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "run":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.RunCommand(ctx, args)
	case "status":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.StatusCommand(ctx, args)
	case "runs":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.RunsCommand(ctx, args)
	case "view":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.ViewCommand(ctx, args)
	case "inspect":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.InspectCommand(ctx, args)
	case "query":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.QueryCommand(ctx, args)
	case "explain":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.ExplainCommand(ctx, args)
	case "residual":
		args = normalizeSubcommandHelpArgs(args)
		err = cli.ResidualCommand(ctx, args)
	case "_exec_in_cgroup":
		// Internal helper used by `logira run` to join a delegated cgroup before exec.
		err = cli.ExecInCgroupCommand(ctx, args)
	case "help", "-h", "--help":
		return runHelp(ctx, prog, args)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		printRootHelp(os.Stderr, prog)
		return 2
	}

	if err != nil {
		if code, ok := commandExitCode(err); ok {
			return code
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func commandExitCode(err error) (int, bool) {
	if errors.Is(err, flag.ErrHelp) {
		return 0, true
	}
	var exitErr *cli.ExitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.Code, true
	}
	return 0, false
}

func normalizeSubcommandHelpArgs(args []string) []string {
	// Support: `logira <subcommand> help`
	if len(args) > 0 && args[0] == "help" {
		return []string{"-h"}
	}
	return args
}

func runHelp(ctx context.Context, prog string, args []string) int {
	// `logira -h`, `logira help`
	if len(args) == 0 {
		printRootHelp(os.Stdout, prog)
		return 0
	}

	// `logira help <subcommand>`
	sub := args[0]
	switch sub {
	case "run":
		_ = cli.RunCommand(ctx, []string{"-h"})
		return 0
	case "status":
		_ = cli.StatusCommand(ctx, []string{"-h"})
		return 0
	case "runs":
		_ = cli.RunsCommand(ctx, []string{"-h"})
		return 0
	case "view":
		_ = cli.ViewCommand(ctx, []string{"-h"})
		return 0
	case "inspect":
		_ = cli.InspectCommand(ctx, []string{"-h"})
		return 0
	case "query":
		_ = cli.QueryCommand(ctx, []string{"-h"})
		return 0
	case "explain":
		_ = cli.ExplainCommand(ctx, []string{"-h"})
		return 0
	case "residual":
		_ = cli.ResidualCommand(ctx, []string{"-h"})
		return 0
	default:
		_, _ = fmt.Fprintf(os.Stderr, "unknown command %q\n\n", sub)
		printRootHelp(os.Stderr, prog)
		return 2
	}
}

func printRootHelp(w io.Writer, prog string) {
	_, _ = fmt.Fprintf(w, "%s: Linux-only CLI auditor (exec/file/net)\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s <command> [args]\n", prog)
	_, _ = fmt.Fprintf(w, "  %s help [command]\n\n", prog)

	_, _ = fmt.Fprintln(w, "Commands:")
	_, _ = fmt.Fprintln(w, "  run        Run a command under audit (auto-saves a new run).")
	_, _ = fmt.Fprintln(w, "  status     Check if logira is ready on this machine.")
	_, _ = fmt.Fprintln(w, "  runs       List saved runs.")
	_, _ = fmt.Fprintln(w, "  view       View a run summary (default: last).")
	_, _ = fmt.Fprintln(w, "  inspect    Inspect one agent action and its observed evidence.")
	_, _ = fmt.Fprintln(w, "  query      Query events in a run (default: last).")
	_, _ = fmt.Fprintln(w, "  explain    Explain detections for a run (default: last).")
	_, _ = fmt.Fprintln(w, "  residual   Compare runtime-reported and kernel-observed actions.")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "Examples:")
	_, _ = fmt.Fprintf(w, "  %s run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'\n", prog)
	_, _ = fmt.Fprintf(w, "  %s status\n", prog)
	_, _ = fmt.Fprintf(w, "  %s runs\n", prog)
	_, _ = fmt.Fprintf(w, "  %s view last\n", prog)
	_, _ = fmt.Fprintf(w, "  %s inspect last action:1\n", prog)
	_, _ = fmt.Fprintf(w, "  %s query --run last --type net --dest 93.184.216.34:443\n", prog)
	_, _ = fmt.Fprintf(w, "  %s explain last\n", prog)
	_, _ = fmt.Fprintf(w, "  %s residual last\n\n", prog)

	_, _ = fmt.Fprintln(w, "Environment:")
	_, _ = fmt.Fprintln(w, "  LOGIRA_HOME           Base directory (default: ~/.logira)")
	_, _ = fmt.Fprintln(w, "  LOGIRA_SOCK           logirad socket path (default: /run/logira.sock)")
	_, _ = fmt.Fprintln(w, "  LOGIRA_EXEC_BPF_OBJ   Override exec BPF object path (Linux only)")
	_, _ = fmt.Fprintln(w, "  LOGIRA_NET_BPF_OBJ    Override net BPF object path (Linux only)")
	_, _ = fmt.Fprintln(w, "  LOGIRA_FILE_BPF_OBJ   Override file BPF object path (Linux only)")
	_, _ = fmt.Fprintln(w)

	_, _ = fmt.Fprintln(w, "Help:")
	_, _ = fmt.Fprintf(w, "  %s -h\n", prog)
	_, _ = fmt.Fprintf(w, "  %s <command> -h\n", prog)
	_, _ = fmt.Fprintf(w, "  %s <command> help\n", prog)
}
