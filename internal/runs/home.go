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

type userHomeFunc func() (string, error)
type readFileFunc func(path string) ([]byte, error)

// HomeDir returns the base directory for logira state.
//
// Default: ~/.logira
// Override: LOGIRA_HOME
func HomeDir() (string, error) {
	return resolveHomeDir(os.Geteuid(), os.Getenv, os.UserHomeDir, func(string) ([]byte, error) {
		return readPasswd()
	})
}

func resolveHomeDir(euid int, getenv func(string) string, userHome userHomeFunc, readFile readFileFunc) (string, error) {
	if v := strings.TrimSpace(getenv("LOGIRA_HOME")); v != "" {
		return v, nil
	}
	// Backward-compat for early versions that used a non-standard env var name.
	if v := strings.TrimSpace(getenv("logira_HOME")); v != "" {
		return v, nil
	}

	// If invoked via sudo, prefer the invoking user's home so runs are visible
	// to non-root `logira runs/query/view`.
	if euid == 0 {
		if inv, ok := sudoInvokerFromEnv(getenv); ok && inv.UID != 0 {
			if passwd, err := readFile("/etc/passwd"); err == nil {
				if h, ok := lookupHomeFromPasswd(inv.User, inv.UID, passwd); ok {
					return filepath.Join(h, ".logira"), nil
				}
			}
		}
	}

	home, err := userHome()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".logira"), nil
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
		if strings.TrimSpace(os.Getenv("logira_HOME")) != "" {
			ensureHome, ensureErr = ensureHomeDir(home)
			return
		}
		if strings.TrimSpace(os.Getenv("LOGIRA_HOME")) != "" {
			ensureHome, ensureErr = ensureHomeDir(home)
			return
		}

		// Prefer ~/.logira (spec), but fall back if the environment restricts
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
		ensureErr = fmt.Errorf("unable to initialize logira home dir (tried %v)", cands)
	})
	return ensureHome, ensureErr
}

func homeCandidates(primary string) ([]string, error) {
	baseHome := ""
	if filepath.Base(primary) == ".logira" {
		baseHome = filepath.Dir(primary)
	}
	if baseHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return []string{primary}, nil
		}
		baseHome = home
	}

	alt := filepath.Join(baseHome, ".logira2")
	stateHome := strings.TrimSpace(os.Getenv("XDG_STATE_HOME"))
	if stateHome == "" {
		stateHome = filepath.Join(baseHome, ".local", "state")
	}
	tmpUID := os.Getuid()
	if os.Geteuid() == 0 {
		if inv, ok := sudoInvokerFromEnv(os.Getenv); ok && inv.UID > 0 {
			tmpUID = inv.UID
		}
	}
	tmp := filepath.Join(os.TempDir(), "logira-"+strconv.Itoa(tmpUID))
	return []string{
		primary,
		alt,
		filepath.Join(stateHome, "logira"),
		tmp,
	}, nil
}

func ensureHomeDir(home string) (string, error) {
	// Home contains audit data (command lines, file paths, network destinations).
	// Default to private permissions.
	if err := os.MkdirAll(home, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", home, err)
	}
	if err := os.MkdirAll(filepath.Join(home, "runs"), 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", home, err)
	}
	return home, nil
}

// sqliteWorks checks whether modernc SQLite can create/open a DB under home.
// This is an environment-specific guard: some sandboxes restrict SQLite in
// particular paths (e.g. ~/.logira).
func sqliteWorks(home string) bool {
	// Use a non-hidden filename: some environments restrict SQLite under $HOME
	// for dot-prefixed DB files.
	p := filepath.Join(home, "sqlite_check.sqlite")
	_ = os.Remove(p)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
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
