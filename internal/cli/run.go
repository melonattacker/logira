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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/cgroupv2"
	"github.com/melonattacker/logira/internal/detect"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
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
	fs.Int64Var(&hashMaxBytes, "hash-max-bytes", 10*1024*1024, "max bytes hashed per file")
	fs.BoolVar(&waitChildren, "wait-children", true, "wait until child process tree exits")
	fs.DurationVar(&waitChildrenTimeout, "wait-children-timeout", 5*time.Second, "max wait for child tree drain")

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
	runDir := runs.RunDir(home, runID)
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", runDir, err)
	}

	cwd, _ := os.Getwd()
	startTS := now.UTC().UnixNano()
	meta := runs.Meta{
		RunID:       runID,
		StartTS:     startTS,
		Tool:        runs.SanitizeTool(tool),
		Command:     strings.Join(cmdArgs, " "),
		CommandArgv: append([]string{}, cmdArgs...),
		CWD:         cwd,
		WatchPaths:  append([]string{}, watch...),
		Version:     2,
	}
	if err := runs.WriteMeta(runDir, meta); err != nil {
		return err
	}

	cfg := collector.Config{
		EnableExec:   enableExec,
		EnableFile:   enableFile,
		EnableNet:    enableNet,
		WatchPaths:   watch,
		ArgvMax:      argvMax,
		ArgvMaxBytes: argvMaxBytes,
		HashMaxBytes: hashMaxBytes,
	}

	col := collector.New(cfg)
	if err := col.Init(ctx); err != nil {
		return err
	}

	metaJSONBytes, _ := json.Marshal(meta)
	store, err := storage.Open(storage.OpenParams{
		RunID:    runID,
		RunDir:   runDir,
		StartTS:  startTS,
		Command:  meta.Command,
		Tool:     meta.Tool,
		MetaJSON: string(metaJSONBytes),
	})
	if err != nil {
		return err
	}
	storeClosed := false
	defer func() {
		if storeClosed {
			return
		}
		_ = store.Close(storage.NowUnixNanos(), string(metaJSONBytes))
	}()

	homeDir, _ := os.UserHomeDir()
	detector := detect.NewEngine(homeDir)

	events := make(chan collector.Event, 4096)
	if err := col.Start(ctx, events); err != nil {
		return err
	}

	var writerWG sync.WaitGroup
	writerWG.Add(1)
	var writerErr error
	var writerMu sync.Mutex
	go func() {
		defer writerWG.Done()
		for ev := range events {
			if err := handleObservedEvent(store, detector, runID, ev); err != nil {
				writerMu.Lock()
				if writerErr == nil {
					writerErr = err
				}
				writerMu.Unlock()
				return
			}
		}
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	var cg *cgroupv2.Cgroup
	if runtime.GOOS == "linux" && cgroupv2.Available() {
		if c, err := cgroupv2.Create(runID); err == nil {
			cg = c
			meta.CgroupPath = c.Path
			_ = runs.WriteMeta(runDir, meta)
		}
	}

	if err := cmd.Start(); err != nil {
		_ = col.Stop(context.Background())
		close(events)
		writerWG.Wait()
		return fmt.Errorf("start agent command: %w", err)
	}

	if cg != nil {
		_ = cg.JoinPID(cmd.Process.Pid)
	}
	if setter, ok := col.(collector.TargetSetter); ok {
		setter.SetTargetPID(cmd.Process.Pid)
	}

	waitErr := cmd.Wait()

	if waitChildren {
		if waiter, ok := col.(collector.ChildWaiter); ok {
			drainCtx, cancel := context.WithTimeout(context.Background(), waitChildrenTimeout)
			_ = waiter.WaitForIdle(drainCtx)
			cancel()
		}
	}
	time.Sleep(500 * time.Millisecond)

	stopErr := col.Stop(context.Background())
	close(events)
	writerWG.Wait()

	writerMu.Lock()
	werr := writerErr
	writerMu.Unlock()
	if werr != nil {
		return fmt.Errorf("write events: %w", werr)
	}

	endTS := storage.NowUnixNanos()
	meta.EndTS = endTS
	meta.SuspiciousCount = store.SuspiciousCount()
	metaJSONBytes, _ = json.Marshal(meta)
	_ = runs.WriteMeta(runDir, meta)
	_ = store.Close(endTS, string(metaJSONBytes))
	storeClosed = true

	if cg != nil {
		_ = cg.Remove()
	}

	if strings.TrimSpace(logPath) != "" {
		_ = copyFile(filepath.Join(runDir, "events.jsonl"), logPath)
	}

	fmt.Fprintf(os.Stderr, "run_id=%s dir=%s suspicious=%d\n", runID, runDir, meta.SuspiciousCount)

	if waitErr != nil {
		if stopErr != nil {
			return fmt.Errorf("command failed: %v (collector stop error: %v)", waitErr, stopErr)
		}
		return waitErr
	}
	if stopErr != nil {
		return stopErr
	}
	return nil
}

func runUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	fmt.Fprintf(w, "%s run: run a command under audit (auto-saves a run)\n\n", prog)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintf(w, "  sudo %s run [flags] -- <agent command...>\n\n", prog)

	fmt.Fprintln(w, "Notes:")
	fmt.Fprintln(w, "  Use '--' to separate logira flags from the audited command.")
	fmt.Fprintln(w, "  Runs are stored under ~/.logira/runs/<run-id>/ (override: LOGIRA_HOME).")
	fmt.Fprintln(w)

	fmt.Fprintln(w, "Examples:")
	fmt.Fprintf(w, "  sudo %s run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'\n", prog)
	fmt.Fprintf(w, "  sudo %s run --watch . --watch /etc -- bash -lc 'cat /etc/hosts >/dev/null'\n", prog)
	fmt.Fprintf(w, "  sudo %s run --exec=false --file=true --net=false -- bash -lc 'echo hi > x.txt'\n\n", prog)

	fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}

func handleObservedEvent(store *storage.Store, detector *detect.Engine, runID string, ev collector.Event) error {
	typ := storage.EventType(ev.Type)
	switch typ {
	case storage.TypeExec, storage.TypeFile, storage.TypeNet:
	default:
		return nil
	}

	ts := storage.NowUnixNanos()

	var summary string
	var attrs storage.EventRow

	switch typ {
	case storage.TypeExec:
		var d model.ExecDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = execSummary(d)
		attrs.Exe = d.Filename
	case storage.TypeFile:
		var d model.FileDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = fmt.Sprintf("file %s %s", d.Op, d.Path)
		attrs.Path = d.Path
	case storage.TypeNet:
		var d model.NetDetail
		_ = json.Unmarshal(ev.Detail, &d)
		summary = fmt.Sprintf("net %s %s:%d bytes=%d", d.Op, d.DstIP, d.DstPort, d.Bytes)
		attrs.DstIP = d.DstIP
		attrs.DstPort = int(d.DstPort)
	}

	seq, err := store.AppendObserved(ts, typ, ev.PID, ev.PPID, ev.UID, summary, ev.Detail, attrs)
	if err != nil {
		return err
	}

	for _, det := range detector.Evaluate(typ, ev.Detail) {
		_, _ = store.AppendDetection(storage.NowUnixNanos(), det, seq)
	}
	return nil
}

func execSummary(d model.ExecDetail) string {
	if len(d.Argv) > 0 {
		head := d.Argv
		if len(head) > 3 {
			head = head[:3]
		}
		return "exec " + strings.Join(head, " ")
	}
	if d.Filename != "" {
		return "exec " + d.Filename
	}
	return "exec <unknown>"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}
