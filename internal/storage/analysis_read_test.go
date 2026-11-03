package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestAnalysisReadsAllEventsBeyondQueryLimit(t *testing.T) {
	const count = 100005
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	f, err := os.Create(path) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	db, err := OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := tx.Prepare(`INSERT INTO events(run_id,seq,ts,type,summary,data_json) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stmt.Close() }()
	for i := 1; i <= count; i++ {
		e := Event{RunID: "r", Seq: int64(i), TS: int64(i), Type: TypeFile, Summary: "file", DataJSON: json.RawMessage(`{"op":"unknown"}`)}
		if i == count-1 {
			e.Type = TypeExec
			e.DataJSON = json.RawMessage(`{"filename":"/bin/sh","tid":10,"task_start_kernel_ns":10,"kernel_time_ns":20}`)
		}
		if i == count {
			e.DataJSON = json.RawMessage(`{"op":"modify","tid":10,"kernel_time_ns":30}`)
		}
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
		if _, err := stmt.Exec(e.RunID, e.Seq, e.TS, string(e.Type), e.Summary, string(e.DataJSON)); err != nil {
			t.Fatal(err)
		}
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	first, err := ReadAnalysisSnapshot(context.Background(), dir, "r")
	if err != nil {
		t.Fatal(err)
	}
	if first.EventSource != "jsonl" || len(first.Events) != count || first.Events[count-2].Type != TypeExec {
		t.Fatalf("truncated JSONL: source=%s len=%d", first.EventSource, len(first.Events))
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	second, err := ReadAnalysisSnapshot(context.Background(), dir, "r")
	if err != nil {
		t.Fatal(err)
	}
	if second.EventSource != "sqlite" || !reflect.DeepEqual(first.Events, second.Events) {
		t.Fatal("SQLite fallback differs or truncated")
	}
}

func TestAnalysisReadOnlyFallbackMetadataAndDetection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "index.sqlite")
	db, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.InsertRun(RunRow{ID: "r", MetaJSON: `{"run_id":"r","end_ts":10}`}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDetection(DetectionRow{RunID: "r", Seq: 2, RuleID: "test", Message: "message"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	s, err := ReadAnalysisSnapshot(context.Background(), dir, "r")
	if err != nil {
		t.Fatal(err)
	}
	if s.MetadataSource != "sqlite" || len(s.Events) != 1 || s.Events[0].Type != TypeDetection {
		t.Fatalf("snapshot=%+v", s)
	}
	after, err := os.ReadFile(path) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("analysis modified database")
	}
}

func TestAnalysisDoesNotHideCorruptionOrCreateDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte("{bad\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysisSnapshot(context.Background(), dir, "r"); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("corruption error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "index.sqlite")); !os.IsNotExist(err) {
		t.Fatal("created database")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysisSnapshot(context.Background(), dir, "r"); err == nil {
		t.Fatal("accepted missing input")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("reader created files")
	}
}

func TestAnalysisUnsupportedSQLiteAndCancellation(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`PRAGMA user_version=99`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAnalysisSnapshot(context.Background(), dir, "r"); err == nil || !strings.Contains(err.Error(), "version 99") {
		t.Fatalf("error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadAnalysisSnapshot(ctx, dir, "r"); err == nil {
		t.Fatal("ignored cancellation")
	}
}
