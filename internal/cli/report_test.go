package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/runs"
)

func TestParseReportArgsAndDefaultOutput(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		selector string
		output   string
		force    bool
		wantErr  bool
	}{
		{name: "default", selector: "last"},
		{name: "explicit last", args: []string{"last"}, selector: "last"},
		{name: "explicit run", args: []string{"run-1"}, selector: "run-1"},
		{name: "flags only", args: []string{"--html", "--output", "audit.html", "--force"}, selector: "last", output: "audit.html", force: true},
		{name: "flags after run", args: []string{"run-1", "--html", "-o", "audit.html", "--force"}, selector: "run-1", output: "audit.html", force: true},
		{name: "flags before run", args: []string{"--html", "--output", "audit.html", "--force", "run-1"}, selector: "run-1", output: "audit.html", force: true},
		{name: "flags after last", args: []string{"last", "--html", "--output", "audit.html"}, selector: "last", output: "audit.html"},
		{name: "flags before last", args: []string{"-o", "audit.html", "last"}, selector: "last", output: "audit.html"},
		{name: "last then run", args: []string{"last", "run-1"}, wantErr: true},
		{name: "last twice", args: []string{"last", "last"}, wantErr: true},
		{name: "two runs", args: []string{"run-1", "run-2"}, wantErr: true},
		{name: "last then flags then run", args: []string{"last", "--html", "run-1"}, wantErr: true},
		{name: "flags then two runs", args: []string{"--html", "run-1", "run-2"}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selector, output, force, err := parseReportArgs(tc.args)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "at most one run selector") {
					t.Fatalf("error=%v, want multiple-selector error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if selector != tc.selector || output != tc.output || force != tc.force {
				t.Fatalf("unexpected options: selector=%q output=%q force=%v", selector, output, force)
			}
		})
	}
	if got := resolveReportOutputPath("", "run-1"); got != "logira-report-run-1.html" {
		t.Fatalf("default output=%q", got)
	}
	if got := resolveReportOutputPath("custom", "run-1"); got != "custom" {
		t.Fatalf("explicit output was changed: %q", got)
	}
}

func TestWriteReportFileProtectsExistingDataAndForceIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := writeReportFile(path, []byte("first"), false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("report mode=%#o", info.Mode().Perm())
	}
	if err := writeReportFile(path, []byte("second"), false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing report was not protected: %v", err)
	}
	data, _ := os.ReadFile(path) //nolint:gosec // Fixed report filename under t.TempDir(), not user input.
	if string(data) != "first" {
		t.Fatalf("collision changed existing data: %q", data)
	}
	if err := writeReportFile(path, []byte("second"), true); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path) //nolint:gosec // Fixed report filename under t.TempDir(), not user input.
	if string(data) != "second" {
		t.Fatalf("force did not replace data: %q", data)
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".logira-report-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary reports were left behind: %v", matches)
	}
	if err := writeReportFile(filepath.Join(dir, "missing", "report.html"), []byte("x"), false); err == nil {
		t.Fatal("missing parent directory was created or ignored")
	}
}

func TestValidateHTMLReportRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta runs.Meta
		want string
	}{
		{"active", runs.Meta{AgentProvider: "codex"}, "still running"},
		{"non-agent", runs.Meta{EndTS: 1}, "completed Codex agent run"},
		{"provider", runs.Meta{EndTS: 1, AgentProvider: "other"}, "unsupported agent provider"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateHTMLReportRun(tc.meta, "run-1")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
	if err := validateHTMLReportRun(runs.Meta{EndTS: 1, AgentProvider: "codex"}, "run-1"); err != nil {
		t.Fatal(err)
	}
}
