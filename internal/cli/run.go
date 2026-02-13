package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/melonattacker/agentlogix/collector"
	"github.com/melonattacker/agentlogix/internal/logging"
)

func RunCommand(ctx context.Context, args []string) error {
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep == -1 {
		return errors.New("run expects '-- <agent command...>'")
	}

	flagArgs := args[:sep]
	cmdArgs := args[sep+1:]
	if len(cmdArgs) == 0 {
		return errors.New("no agent command provided")
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var logPath string
	var watch stringSliceFlag
	var enableExec bool
	var enableFile bool
	var enableNet bool
	var argvMax int
	var argvMaxBytes int
	var hashMaxBytes int64
	var waitChildren bool
	var waitChildrenTimeout time.Duration

	fs.StringVar(&logPath, "log", "", "output JSONL log file path (required)")
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
	if strings.TrimSpace(logPath) == "" {
		return errors.New("--log is required")
	}
	if len(watch) == 0 {
		watch = append(watch, ".")
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

	writer, err := logging.NewJSONLWriter(logPath)
	if err != nil {
		return err
	}
	defer writer.Close()

	events := make(chan collector.Event, 4096)
	if err := col.Start(ctx, events); err != nil {
		return err
	}

	var dropped atomic.Uint64
	var writerWG sync.WaitGroup
	writerWG.Add(1)
	go func() {
		defer writerWG.Done()
		for ev := range events {
			if err := writer.WriteEvent(ev); err != nil {
				dropped.Add(1)
			}
		}
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	if err := cmd.Start(); err != nil {
		_ = col.Stop(context.Background())
		close(events)
		writerWG.Wait()
		return fmt.Errorf("start agent command: %w", err)
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

	if dropped.Load() > 0 {
		fmt.Fprintf(os.Stderr, "warning: failed to write %d events\n", dropped.Load())
	}

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
