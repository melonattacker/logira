package cliui

import (
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	if got := Truncate("abcdef", 5); got != "ab..." {
		t.Fatalf("truncate: got %q", got)
	}
	if got := Truncate("abc", 5); got != "abc" {
		t.Fatalf("no truncate: got %q", got)
	}
}

func TestFormatTimestamp(t *testing.T) {
	start := int64(1_000_000_000)
	ts := start + int64(2_500_000_000)
	if got := FormatTimestamp(ts, start, TSRel); got != "+2.5s" {
		t.Fatalf("rel: got %q", got)
	}
	if got := FormatTimestamp(ts, start, TSBoth); !strings.Contains(got, "+2.5s") {
		t.Fatalf("both: got %q", got)
	}
}

func TestRenderTable(t *testing.T) {
	out := SprintTable(
		[]Column{
			{Name: "a", MaxWidth: 3},
			{Name: "b", MaxWidth: 5},
		},
		[][]string{
			{"1", "hello world"},
		},
	)
	if !strings.Contains(out, "a") || !strings.Contains(out, "he...") {
		t.Fatalf("unexpected table output: %q", out)
	}
}

func TestRenderTable_ANSIWidth(t *testing.T) {
	coloredExec := "\x1b[32mexec\x1b[0m"
	out := SprintTable(
		[]Column{
			{Name: "type", MaxWidth: 10},
			{Name: "pid", MaxWidth: 6},
		},
		[][]string{
			{coloredExec, "123"},
		},
	)
	plain := stripANSI(out)
	if strings.Contains(plain, "ex...") {
		t.Fatalf("ansi cell should not be truncated by hidden escape bytes: %q", plain)
	}
	if !strings.Contains(plain, "exec") {
		t.Fatalf("expected plain output to include exec: %q", plain)
	}
}
