package cgroupv2

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// CreateDelegated creates a cgroup v2 directory under /sys/fs/cgroup/logira/<uid>/<session>
// and attempts to delegate cgroup.procs write access to uid/gid.
//
// This is intended for the root daemon to create per-run cgroups which the user CLI
// can join without sudo.
func CreateDelegated(runID string, uid, gid int, sessionID string) (*Cgroup, error) {
	if !Available() {
		return nil, fmt.Errorf("cgroup v2 not available under %s", MountPoint)
	}
	if uid <= 0 || gid <= 0 {
		return nil, fmt.Errorf("invalid uid/gid")
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil, fmt.Errorf("empty session id")
	}
	// runID is not part of the path (session is), but validate for logging.
	_ = strings.TrimSpace(runID)

	dir := filepath.Join(MountPoint, "logira", strconv.Itoa(uid), sessionID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// Best-effort delegation: chown the directory and key control files.
	_ = os.Chown(dir, uid, gid)
	_ = os.Chmod(dir, 0o755)
	for _, f := range []string{"cgroup.procs", "cgroup.threads"} {
		p := filepath.Join(dir, f)
		_ = os.Chown(p, uid, gid)
		_ = os.Chmod(p, 0o664)
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

// JoinSelf moves the current process into cg by writing its pid to cgroup.procs.
func (cg *Cgroup) JoinSelf() error {
	return cg.JoinPID(os.Getpid())
}

func (cg *Cgroup) Remove() error {
	// Best-effort cleanup. This may fail if processes are still in the cgroup.
	return os.Remove(cg.Path)
}

// CgroupID returns a stable numeric identifier for a cgroup directory.
// For cgroup v2 this is commonly treated as the directory inode number,
// which matches bpf_get_current_cgroup_id().
func CgroupID(cgroupPath string) (uint64, error) {
	st, err := os.Stat(cgroupPath)
	if err != nil {
		return 0, err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys == nil {
		return 0, fmt.Errorf("stat_t unavailable for %s", cgroupPath)
	}
	return sys.Ino, nil
}
