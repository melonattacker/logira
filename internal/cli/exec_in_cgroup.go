package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/melonattacker/logira/internal/ipc"
)

func ExecInCgroupCommand(ctx context.Context, args []string) error {
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

	fs := flag.NewFlagSet("_exec_in_cgroup", flag.ContinueOnError)
	fs.SetOutput(ioDiscard{})

	var cgroupPath string
	var sessionID string
	fs.StringVar(&cgroupPath, "cgroup-path", "", "cgroup v2 path")
	fs.StringVar(&sessionID, "session-id", "", "logirad session id")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	cgroupPath = strings.TrimSpace(cgroupPath)
	sessionID = strings.TrimSpace(sessionID)
	if cgroupPath == "" || sessionID == "" {
		return fmt.Errorf("missing --cgroup-path/--session-id")
	}
	if len(cmdArgs) == 0 {
		return fmt.Errorf("missing command after --")
	}

	if err := joinCgroupSelf(ctx, cgroupPath, sessionID); err != nil {
		return err
	}

	target, err := exec.LookPath(cmdArgs[0])
	if err != nil {
		return err
	}
	return syscall.Exec(target, cmdArgs, os.Environ())
}

func joinCgroupSelf(ctx context.Context, cgroupPath, sessionID string) error {
	p := filepath.Join(cgroupPath, "cgroup.procs")
	if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())), 0o644); err == nil {
		return nil
	}

	// Fallback: ask logirad to attach.
	c, err := ipc.Dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.AttachPID(ctx, sessionID, os.Getpid()); err != nil {
		return err
	}
	// Best-effort re-check.
	if err := os.WriteFile(p, []byte(strconv.Itoa(os.Getpid())), 0o644); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	return nil
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
