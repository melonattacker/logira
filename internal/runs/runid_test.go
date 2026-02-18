package runs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSanitizeTool(t *testing.T) {
	if got := SanitizeTool(" Git "); got != "git" {
		t.Fatalf("got %q", got)
	}
	if got := SanitizeTool("curl|sh"); got == "" || got == "curl|sh" {
		t.Fatalf("unexpected %q", got)
	}
	if got := SanitizeTool("###"); got != "unknown" {
		t.Fatalf("got %q", got)
	}
}

func TestNewRunID_Unique(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "runs"), 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 2, 14, 1, 2, 3, 0, time.UTC)
	id1, err := NewRunID(home, "tool", now)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != "20260214-010203-tool" {
		t.Fatalf("id1=%q", id1)
	}
	if err := os.MkdirAll(filepath.Join(home, "runs", id1), 0o700); err != nil {
		t.Fatal(err)
	}
	id2, err := NewRunID(home, "tool", now)
	if err != nil {
		t.Fatal(err)
	}
	if id2 != "20260214-010203-tool-2" {
		t.Fatalf("id2=%q", id2)
	}
}

func TestValidateRunID(t *testing.T) {
	ok := []string{
		"20260214-010203-tool",
		"abc-123_DEF.ghi",
	}
	for _, id := range ok {
		if err := ValidateRunID(id); err != nil {
			t.Fatalf("ValidateRunID(%q) unexpected err: %v", id, err)
		}
	}

	bad := []string{
		"",
		".",
		"..",
		"../x",
		"..\\x",
		"a/b",
		"a\\b",
		" has space ",
		"nul\x00byte",
	}
	for _, id := range bad {
		if err := ValidateRunID(id); err == nil {
			t.Fatalf("ValidateRunID(%q) expected err", id)
		}
	}
}
