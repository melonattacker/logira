package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/melonattacker/logira/internal/ipc"
	"github.com/melonattacker/logira/internal/runs"
)

func RunCommand(ctx context.Context, args []string) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}

	flagArgs := args
	var cmdArgs []string
	if sep != -1 {
		flagArgs = args[:sep]
		cmdArgs = args[sep+1:]
	}

	fs := newFlagSet("run", flagArgs, runUsage)

	var logPath string
	var watch stringSliceFlag
	var enableExec bool
	var enableFile bool
	var enableNet bool
	var tool string
	var argvMax int
	var argvMaxBytes int
	var hashMaxBytes int64
	var waitChildren bool
	var waitChildrenTimeout time.Duration

	fs.StringVar(&logPath, "log", "", "deprecated: optional extra copy of events.jsonl written to this path")
	fs.StringVar(&tool, "tool", "", "tool name for run id suffix (default: basename of the command)")
	fs.Var(&watch, "watch", "watch path for file events (repeatable)")
	fs.BoolVar(&enableExec, "exec", true, "enable exec tracing")
	fs.BoolVar(&enableFile, "file", true, "enable file tracing")
	fs.BoolVar(&enableNet, "net", true, "enable network tracing")
	fs.IntVar(&argvMax, "argv-max", 20, "max argv entries")
	fs.IntVar(&argvMaxBytes, "argv-max-bytes", 256, "max bytes per argv entry")
	fs.Int64Var(&hashMaxBytes, "hash-max-bytes", 10*1024*1024, "max bytes hashed per file (legacy; may be ignored)")
	fs.BoolVar(&waitChildren, "wait-children", true, "wait until cgroup process tree exits")
	fs.DurationVar(&waitChildrenTimeout, "wait-children-timeout", 5*time.Second, "max wait for cgroup to drain")

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	if sep == -1 {
		fs.Usage()
		return errors.New("run expects '-- <agent command...>'")
	}
	if len(cmdArgs) == 0 {
		fs.Usage()
		return errors.New("no agent command provided")
	}
	if len(watch) == 0 {
		watch = append(watch, ".")
	}

	if strings.TrimSpace(logPath) != "" {
		fmt.Fprintln(os.Stderr, "warning: --log is deprecated; events are always stored under ~/.logira/runs/<run-id>/")
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}

	if strings.TrimSpace(tool) == "" {
		tool = filepath.Base(cmdArgs[0])
	}
	now := time.Now()
	runID, err := runs.NewRunID(home, tool, now)
	if err != nil {
		return err
	}

	cwd, _ := os.Getwd()

	cliSock := ipc.SockPath()
	client, err := ipc.Dial(ctx)
	if err != nil {
		return fmt.Errorf("connect logirad (%s): %w", cliSock, err)
	}
	defer client.Close()

	startReq := ipc.StartRunRequest{
		RunID:      runID,
		Tool:       tool,
		CmdArgv:    append([]string{}, cmdArgs...),
		CWD:        cwd,
		LogiraHome: home,

		EnableExec: enableExec,
		EnableFile: enableFile,
		EnableNet:  enableNet,

		WatchPaths:   append([]string{}, watch...),
		ArgvMax:      argvMax,
		ArgvMaxBytes: argvMaxBytes,
		HashMaxBytes: hashMaxBytes,
	}

	startResp, err := client.StartRun(ctx, startReq)
	if err != nil {
		return err
	}

	// Run the audited command via an internal helper which joins the cgroup
	// before exec to avoid missing the first exec event.
	self, err := os.Executable()
	if err != nil {
		return err
	}
	helperArgs := []string{
		"_exec_in_cgroup",
		"--cgroup-path", startResp.CgroupPath,
		"--session-id", startResp.SessionID,
		"--",
	}
	helperArgs = append(helperArgs, cmdArgs...)

	cmd := exec.CommandContext(ctx, self, helperArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		_ = client.StopRun(context.Background(), startResp.SessionID, 127)
		return fmt.Errorf("start agent command: %w", err)
	}

	waitErr := cmd.Wait()
	exitCode := exitCodeFromErr(waitErr)

	if waitChildren {
		drainCtx, cancel := context.WithTimeout(context.Background(), waitChildrenTimeout)
		_ = waitForCgroupEmpty(drainCtx, startResp.CgroupPath)
		cancel()
	}

	stopErr := stopRunWithRetry(client, startResp.SessionID, exitCode)

	// Best-effort: read meta for suspicious_count.
	sus := 0
	if b, err := os.ReadFile(runs.MetaPath(startResp.RunDir)); err == nil {
		var m runs.Meta
		if json.Unmarshal(b, &m) == nil {
			sus = m.SuspiciousCount
		}
	}

	if strings.TrimSpace(logPath) != "" {
		_ = copyFile(filepath.Join(startResp.RunDir, "events.jsonl"), logPath)
	}

	fmt.Fprintf(os.Stderr, "run_id=%s dir=%s suspicious=%d\n", runID, startResp.RunDir, sus)

	if stopErr != nil {
		if waitErr != nil {
			return fmt.Errorf("%w (also failed to finalize run: %v)", waitErr, stopErr)
		}
		return fmt.Errorf("finalize run: %w", stopErr)
	}

	if waitErr != nil {
		return waitErr
	}
	return nil
}

func stopRunWithRetry(client *ipc.Client, sessionID string, exitCode int) error {
	tryStop := func(c *ipc.Client) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		err := c.StopRun(ctx, sessionID, exitCode)
		if err == nil || isUnknownSessionErr(err) {
			return nil
		}
		return err
	}

	if err := tryStop(client); err == nil {
		return nil
	}

	var lastErr error
	for i := 0; i < 4; i++ {
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)

		c, err := ipc.Dial(context.Background())
		if err != nil {
			lastErr = err
			continue
		}
		err = tryStop(c)
		_ = c.Close()
		if err == nil {
			return nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("unknown error")
	}
	return lastErr
}

func isUnknownSessionErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unknown session_id")
}

func runUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s run: run a command under audit (auto-saves a run)\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  %s run [flags] -- <agent command...>\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  Requires logirad (root daemon) to be running.")
	fmt.Fprintln(w, "  Use '--' to separate logira flags from the audited command.")
	fmt.Fprintln(w, "  Runs are stored under ~/.logira/runs/<run-id>/ (override: LOGIRA_HOME).")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  %s run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'\n", prog)
	fmt.Fprintf(w, "  %s run --watch . --watch /etc -- bash -lc 'echo hi > x.txt; cat /etc/hosts >/dev/null'\n", prog)
	fmt.Fprintf(w, "  %s run --exec=false --file=true --net=false -- bash -lc 'echo hi > x.txt'\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}

func exitCodeFromErr(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if st, ok := ee.Sys().(syscall.WaitStatus); ok {
			if st.Signaled() {
				return 128 + int(st.Signal())
			}
			return st.ExitStatus()
		}
	}
	return 1
}
