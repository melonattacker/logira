package runs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveHomeDir_LOGIRA_HOMEWins(t *testing.T) {
	getenv := func(k string) string {
		if k == "LOGIRA_HOME" {
			return "/tmp/custom"
		}
		return ""
	}
	userHome := func() (string, error) { return "/home/ignored", nil }
	readFile := func(path string) ([]byte, error) { return nil, os.ErrNotExist }

	got, err := resolveHomeDir(1000, getenv, userHome, readFile)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != "/tmp/custom" {
		t.Fatalf("got %q", got)
	}
}

func TestResolveHomeDir_SudoUsesInvokerHome(t *testing.T) {
	getenv := func(k string) string {
		switch k {
		case "SUDO_USER":
			return "alice"
		case "SUDO_UID":
			return "1000"
		case "SUDO_GID":
			return "1000"
		default:
			return ""
		}
	}
	userHome := func() (string, error) { return "/root", nil }
	readFile := func(path string) ([]byte, error) {
		if path != "/etc/passwd" {
			return nil, os.ErrNotExist
		}
		return []byte("alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"), nil
	}

	got, err := resolveHomeDir(0, getenv, userHome, readFile)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := filepath.Join("/home/alice", ".logira")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveHomeDir_SudoFallsBackWhenPasswdMissing(t *testing.T) {
	getenv := func(k string) string {
		switch k {
		case "SUDO_USER":
			return "alice"
		case "SUDO_UID":
			return "1000"
		case "SUDO_GID":
			return "1000"
		default:
			return ""
		}
	}
	userHome := func() (string, error) { return "/root", nil }
	readFile := func(path string) ([]byte, error) { return nil, os.ErrNotExist }

	got, err := resolveHomeDir(0, getenv, userHome, readFile)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := filepath.Join("/root", ".logira")
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestResolveHomeDir_UserHomeError(t *testing.T) {
	getenv := func(string) string { return "" }
	userHome := func() (string, error) { return "", errors.New("boom") }
	readFile := func(path string) ([]byte, error) { return nil, os.ErrNotExist }

	_, err := resolveHomeDir(1000, getenv, userHome, readFile)
	if err == nil {
		t.Fatalf("expected error")
	}
}

