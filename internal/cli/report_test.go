package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/storage"
)

const reportRunID = "20261103-010101-shell"

func reportFixture(t *testing.T, withMeta bool) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("LOGIRA_HOME", home)
	dir := filepath.Join(home, "runs", reportRunID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := `{"run_id":"20261103-010101-shell","seq":1,"ts":1,"type":"exec","summary":"exec sh","data_json":{"filename":"/bin/sh","argv":["sh","-c","echo hi"],"tid":10,"tgid":10,"task_start_kernel_ns":10,"kernel_time_ns":20}}
{"run_id":"20261103-010101-shell","seq":2,"ts":2,"type":"process","summary":"fork","data_json":{"kind":"fork","parent_tid":10,"parent_task_start_kernel_ns":10,"child_tid":11,"task_start_kernel_ns":30,"kernel_time_ns":31,"clone_kind":"unknown"}}
{"run_id":"20261103-010101-shell","seq":3,"ts":3,"type":"file","summary":"file create_or_open out","data_json":{"op":"create_or_open","tid":11,"task_start_kernel_ns":30,"kernel_time_ns":40,"path":"out","path_resolution":"unresolved"}}
`
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	if withMeta {
		if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"run_id":"20261103-010101-shell","command":"sh -c echo hi","start_ts":1,"end_ts":100,"version":5}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestParseReportArgsAndDefaultNames(t *testing.T) {
	for _, tc := range []struct {
		name, selector, output string
		args                   []string
		seq                    int64
		force, wantErr         bool
	}{
		{name: "default", selector: "last"},
		{name: "selector first", args: []string{reportRunID, "--exec-seq", "3", "-o", "audit.html", "--force"}, selector: reportRunID, output: "audit.html", seq: 3, force: true},
		{name: "flags first", args: []string{"--exec-seq", "3", "--output", "audit.html", reportRunID}, selector: reportRunID, output: "audit.html", seq: 3},
		{name: "zero", args: []string{"--exec-seq", "0"}, wantErr: true},
		{name: "negative", args: []string{"--exec-seq", "-2"}, wantErr: true},
		{name: "bad", args: []string{"--exec-seq", "x"}, wantErr: true},
		{name: "two selectors", args: []string{"last", reportRunID}, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := parseReportArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatal("accepted invalid arguments")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.selector != tc.selector || opts.output != tc.output || opts.force != tc.force || opts.execSeq.value != tc.seq {
				t.Fatalf("options=%+v", opts)
			}
		})
	}
	if got := reportOutputPath("", "run-1", optionalExecSeq{}); got != "logira-report-run-1.html" {
		t.Fatalf("overview name=%q", got)
	}
	if got := reportOutputPath("", "run-1", optionalExecSeq{value: 11, set: true}); got != "logira-report-run-1-exec-11.html" {
		t.Fatalf("Episode name=%q", got)
	}
}

func TestReportCLIOverviewEpisodeMissingMetadataAndNoSourceWrites(t *testing.T) {
	dir := reportFixture(t, true)
	eventsPath := filepath.Join(dir, "events.jsonl")
	before, err := os.ReadFile(eventsPath) //nolint:gosec // Test fixture path under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	for _, tc := range []struct {
		name     string
		args     []string
		want     string
		wantFile bool
	}{
		{"overview last", []string{"last", "-o", filepath.Join(outDir, "overview.html")}, "Run Overview", false},
		{"episode explicit", []string{reportRunID, "--exec-seq", "1", "-o", filepath.Join(outDir, "episode.html")}, "Episode Detail", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout bytes.Buffer
			if err := reportCommand(context.Background(), tc.args, &stdout); err != nil {
				t.Fatal(err)
			}
			path := strings.TrimSpace(stdout.String())
			data, err := os.ReadFile(path) //nolint:gosec // Test-selected path under t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(tc.want)) || (tc.wantFile && !bytes.Contains(data, []byte("create_or_open"))) {
				t.Fatalf("report missing %q", tc.want)
			}
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("mode=%#o", info.Mode().Perm())
			}
		})
	}
	after, _ := os.ReadFile(eventsPath) //nolint:gosec // Test fixture path under t.TempDir.
	if !bytes.Equal(before, after) {
		t.Fatal("report changed source events")
	}

	if err := os.Remove(filepath.Join(dir, "meta.json")); err != nil {
		t.Fatal(err)
	}
	missingOut := filepath.Join(outDir, "missing-meta.html")
	if err := reportCommand(context.Background(), []string{"-o", missingOut}, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(missingOut) //nolint:gosec // Test path.
	if !bytes.Contains(data, []byte("Finalization unknown")) || !bytes.Contains(data, []byte("Run metadata is missing")) {
		t.Fatal("missing metadata state was not disclosed")
	}
}

func TestReportCLISQLiteFallbackAndInvalidSelection(t *testing.T) {
	dir := reportFixture(t, true)
	events, err := storage.ReadJSONL(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range events {
		if err := db.InsertEvent(storage.EventRow{RunID: ev.RunID, Seq: ev.Seq, TS: ev.TS, Type: string(ev.Type), Summary: ev.Summary, DataJSON: string(ev.DataJSON)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "sqlite.html")
	if err := reportCommand(context.Background(), []string{"--exec-seq", "1", "-o", out}, io.Discard); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(out) //nolint:gosec // Test path.
	if !bytes.Contains(data, []byte("source sqlite")) {
		t.Fatal("SQLite source was not reported")
	}
	for _, seq := range []string{"2", "999"} {
		if err := reportCommand(context.Background(), []string{"--exec-seq", seq, "-o", filepath.Join(t.TempDir(), "bad.html")}, io.Discard); err == nil {
			t.Fatalf("accepted invalid root %s", seq)
		}
	}
}

func TestWriteReportFileAtomicProtectionAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	render := func(value string) func(io.Writer) error {
		return func(w io.Writer) error { _, err := io.WriteString(w, value); return err }
	}
	if err := writeReportFile(path, false, render("first")); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(path, false, render("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("existing file error=%v", err)
	}
	if data, _ := os.ReadFile(path); string(data) != "first" { //nolint:gosec // Test-selected path under t.TempDir.
		t.Fatalf("existing output changed: %q", data)
	}
	if err := writeReportFile(path, true, render("second")); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "second" { //nolint:gosec // Test-selected path under t.TempDir.
		t.Fatalf("force output=%q", data)
	}

	target := filepath.Join(dir, "target.txt")
	link := filepath.Join(dir, "link.html")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(link, false, render("bad")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("no-force symlink error=%v", err)
	}
	if err := writeReportFile(link, true, render("bad")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("force symlink error=%v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "target" { //nolint:gosec // Test-selected path under t.TempDir.
		t.Fatalf("symlink target changed: %q", data)
	}
	if info, _ := os.Lstat(link); info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("destination symlink was replaced")
	}

	directory := filepath.Join(dir, "directory")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeReportFile(directory, true, render("bad")); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("directory error=%v", err)
	}
	failing := filepath.Join(dir, "failing.html")
	wantErr := errors.New("render failed")
	if err := writeReportFile(failing, false, func(io.Writer) error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("render error=%v", err)
	}
	if _, err := os.Stat(failing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed render installed an output")
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, ".logira-report-*.tmp")); len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func TestReportLimitWriterFailsExplicitly(t *testing.T) {
	var dst bytes.Buffer
	w := &reportLimitWriter{w: &dst, remaining: 3}
	n, err := w.Write([]byte("abcdef"))
	if n != 3 || !errors.Is(err, errReportTooLarge) || dst.String() != "abc" {
		t.Fatalf("n=%d err=%v data=%q", n, err, dst.String())
	}
}

func TestReportCorruptJSONLDoesNotCreateOutput(t *testing.T) {
	dir := reportFixture(t, true)
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("{bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bad.html")
	if err := reportCommand(context.Background(), []string{"-o", out}, io.Discard); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("corruption error=%v", err)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("corrupt input created output")
	}
}
