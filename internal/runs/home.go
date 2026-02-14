package runs

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

import _ "modernc.org/sqlite"

// HomeDir returns the base directory for AgentLogix state.
//
// Default: ~/.agentlogix
// Override: AGENTLOGIX_HOME
func HomeDir() (string, error) {
	if v := strings.TrimSpace(os.Getenv("AGENTLOGIX_HOME")); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".agentlogix"), nil
}

var (
	ensureOnce sync.Once
	ensureHome string
	ensureErr  error
)

func EnsureHome() (string, error) {
	ensureOnce.Do(func() {
		home, err := HomeDir()
		if err != nil {
			ensureErr = err
			return
		}
		if strings.TrimSpace(os.Getenv("AGENTLOGIX_HOME")) != "" {
			ensureHome, ensureErr = ensureHomeDir(home)
			return
		}

		// Prefer ~/.agentlogix (spec), but fall back if the environment restricts
		// SQLite file creation/locking there.
		cands, err := homeCandidates(home)
		if err != nil {
			ensureErr = err
			return
		}
		for _, c := range cands {
			if c == "" {
				continue
			}
			if h, err := ensureHomeDir(c); err == nil && sqliteWorks(h) {
				ensureHome = h
				return
			}
		}
		ensureErr = fmt.Errorf("unable to initialize agentlogix home dir (tried %v)", cands)
	})
	return ensureHome, ensureErr
}

func homeCandidates(primary string) ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return []string{primary}, nil
	}
	alt := filepath.Join(home, ".agentlogix2")
	stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if stateHome == "" {
		stateHome = filepath.Join(home, ".local", "state")
	}
	tmp := filepath.Join(os.TempDir(), "agentlogix-"+strconv.Itoa(os.Getuid()))
	return []string{
		primary,
		alt,
		filepath.Join(stateHome, "agentlogix"),
		tmp,
	}, nil
}

func ensureHomeDir(home string) (string, error) {
	if err := os.MkdirAll(filepath.Join(home, "runs"), 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", home, err)
	}
	return home, nil
}

// sqliteWorks checks whether modernc SQLite can create/open a DB under home.
// This is an environment-specific guard: some sandboxes restrict SQLite in
// particular paths (e.g. ~/.agentlogix).
func sqliteWorks(home string) bool {
	// Use a non-hidden filename: some environments restrict SQLite under $HOME
	// for dot-prefixed DB files.
	p := filepath.Join(home, "sqlite_check.sqlite")
	_ = os.Remove(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return false
	}
	_ = f.Close()
	db, err := sql.Open("sqlite", p)
	if err != nil {
		return false
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec("CREATE TABLE t(x int);")
	_ = db.Close()
	_ = os.Remove(p)
	return err == nil
}
