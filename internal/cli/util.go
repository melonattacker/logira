package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func copyFile(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // compatibility copy reads a user-requested logira output path.
	if err != nil {
		return err
	}
	defer func() {
		_ = in.Close()
	}()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) //nolint:gosec // compatibility copy writes to a user-requested destination.
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

func waitForCgroupEmpty(ctx context.Context, cgroupPath string) error {
	p := filepath.Join(strings.TrimSpace(cgroupPath), "cgroup.procs")
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		b, err := os.ReadFile(p) //nolint:gosec // cgroup path is created by logira/logirad for this run.
		if err == nil {
			// cgroup.procs contains one PID per line.
			if strings.TrimSpace(string(b)) == "" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait cgroup empty: %w", ctx.Err())
		case <-t.C:
		}
	}
}
