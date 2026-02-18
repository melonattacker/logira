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
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func waitForCgroupEmpty(ctx context.Context, cgroupPath string) error {
	p := filepath.Join(strings.TrimSpace(cgroupPath), "cgroup.procs")
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		b, err := os.ReadFile(p)
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
