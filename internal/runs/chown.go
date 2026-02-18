package runs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// SudoInvoker returns the sudo-invoking user's uid/gid when running as root under sudo.
func SudoInvoker() (uid int, gid int, ok bool) {
	if os.Geteuid() != 0 {
		return 0, 0, false
	}
	inv, ok := sudoInvokerFromEnv(os.Getenv)
	if !ok {
		return 0, 0, false
	}
	if inv.UID <= 0 || inv.GID <= 0 {
		return 0, 0, false
	}
	if inv.UID == 0 {
		return 0, 0, false
	}
	return inv.UID, inv.GID, true
}

// BestEffortChownTreeToSudoUser chowns path (recursively) to the sudo-invoking user.
// It is intentionally best-effort: failures are ignored unless traversal itself fails.
func BestEffortChownTreeToSudoUser(path string) error {
	uid, gid, ok := SudoInvoker()
	if !ok {
		return nil
	}
	return bestEffortChownTree(path, uid, gid)
}

// BestEffortChownTree chowns path (recursively) to uid/gid.
// It is intentionally best-effort: failures are ignored unless traversal itself fails.
func BestEffortChownTree(path string, uid, gid int) error {
	if uid <= 0 || gid <= 0 {
		return nil
	}
	return bestEffortChownTree(path, uid, gid)
}

func bestEffortChownTree(root string, uid, gid int) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	// If root is a file, just chown it.
	if !info.IsDir() {
		// Use Lchown so symlinks cannot be abused to chown arbitrary targets.
		_ = os.Lchown(root, uid, gid)
		return nil
	}

	var walkErr error
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// Propagate actual traversal errors.
			walkErr = err
			return err
		}
		// Ignore per-file chown errors. Root should normally succeed, but we
		// prefer usability over failing the whole run.
		// Use Lchown so symlinks cannot be abused to chown arbitrary targets.
		_ = os.Lchown(p, uid, gid)
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, os.ErrNotExist) {
		return fmt.Errorf("walk %s: %w", root, walkErr)
	}
	return nil
}
