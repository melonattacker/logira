package cgroupv2

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MountPoint = "/sys/fs/cgroup"

type Cgroup struct {
	Path string // absolute path
}

func Available() bool {
	// A minimal check: cgroup v2 exposes cgroup.controllers at the mount root.
	_, err := os.Stat(filepath.Join(MountPoint, "cgroup.controllers"))
	return err == nil
}

// Create creates a cgroup v2 directory under /sys/fs/cgroup/logira/<run-id>.
func Create(runID string) (*Cgroup, error) {
	if !Available() {
		return nil, fmt.Errorf("cgroup v2 not available under %s", MountPoint)
	}
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return nil, fmt.Errorf("empty runID")
	}
	dir := filepath.Join(MountPoint, "logira", runID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return &Cgroup{Path: dir}, nil
}

func (cg *Cgroup) JoinPID(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid pid %d", pid)
	}
	p := filepath.Join(cg.Path, "cgroup.procs")
	return os.WriteFile(p, []byte(strconv.Itoa(pid)), 0o644)
}

func (cg *Cgroup) Remove() error {
	// Best-effort cleanup. This may fail if processes are still in the cgroup.
	return os.Remove(cg.Path)
}
