package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analysis/episode"
	"github.com/melonattacker/logira/internal/storage"
)

const episodeRunID = "20261103-000000-shell"

func episodeFixture(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("LOGIRA_HOME", home)
	dir := filepath.Join(home, "runs", episodeRunID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lines := `{"run_id":"20261103-000000-shell","seq":1,"ts":1,"type":"exec","summary":"exec sh","data_json":{"filename":"/bin/sh","argv":["sh","-c","echo hi"],"tid":10,"task_start_kernel_ns":10,"kernel_time_ns":20}}
{"run_id":"20261103-000000-shell","seq":2,"ts":2,"type":"process","summary":"fork","data_json":{"kind":"fork","parent_tid":10,"parent_task_start_kernel_ns":10,"child_tid":11,"task_start_kernel_ns":30,"kernel_time_ns":31}}
{"run_id":"20261103-000000-shell","seq":3,"ts":3,"type":"file","summary":"file create_or_open out","data_json":{"op":"create_or_open","tid":11,"kernel_time_ns":40,"path":"out","path_resolution":"unresolved"}}
`
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"run_id":"20261103-000000-shell","end_ts":100,"version":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestEpisodeCLITextJSONAndNoWrites(t *testing.T) {
	dir := episodeFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, "events.jsonl")) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"last", "--exec-seq", "1", "--json"}, {"--json", "--exec-seq=1", episodeRunID}, {"--exec-seq", "1", "--json"}} {
		var out bytes.Buffer
		if err := episodeCommand(context.Background(), args, &out); err != nil {
			t.Fatal(err)
		}
		var ep episode.Episode
		if err := json.Unmarshal(out.Bytes(), &ep); err != nil {
			t.Fatalf("stdout is not one JSON object: %v: %s", err, out.String())
		}
		if ep.RootExecSeq != 1 || ep.Summary.Processes != 2 || len(ep.FileEvents) != 1 || ep.FileEvents[0].ExecSeq != nil {
			t.Fatalf("episode=%+v", ep)
		}
	}
	var out bytes.Buffer
	if err := episodeCommand(context.Background(), []string{"last", "--exec-seq", "1"}, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Episode root exec=1", "Members: 2 tasks, 1 observed execs", "File: 1 attributed"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q: %s", want, out.String())
		}
	}
	after, err := os.ReadFile(filepath.Join(dir, "events.jsonl")) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("changed source events")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal("created storage artifacts")
	}
}

func TestEpisodeCLIErrorsDoNotEmitJSON(t *testing.T) {
	dir := episodeFixture(t)
	for _, args := range [][]string{{"last"}, {"--exec-seq", "0"}, {"--exec-seq", "-1"}, {"--exec-seq", "bogus"}, {"--exec-seq", "9223372036854775808"}, {"last", "--exec-seq", "3", "--json"}, {"last", "--exec-seq", "999"}, {"last", "--exec-seq", "1", "extra"}, {"20261103-000001-missing", "--exec-seq", "1"}} {
		var out bytes.Buffer
		if err := episodeCommand(context.Background(), args, &out); err == nil {
			t.Fatalf("accepted %v", args)
		}
		if out.Len() != 0 {
			t.Fatalf("error emitted JSON: %s", out.String())
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(`{"run_id":"20261103-000000-shell","seq":1,"type":"exec","data_json":{"tid":"bad"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := episodeCommand(context.Background(), []string{"--exec-seq", "1"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "seq 1") {
		t.Fatalf("corruption error=%v", err)
	}
}

func TestEpisodeCLISQLiteFallbackAndNonExecDetection(t *testing.T) {
	dir := episodeFixture(t)
	events, err := storage.ReadJSONL(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	db, err := storage.OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if err := db.InsertEvent(storage.EventRow{RunID: e.RunID, Seq: e.Seq, TS: e.TS, Type: string(e.Type), Summary: e.Summary, DataJSON: string(e.DataJSON)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.InsertDetection(storage.DetectionRow{RunID: episodeRunID, Seq: 4, Message: "test"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := episodeCommand(context.Background(), []string{"--exec-seq", "1", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var ep episode.Episode
	if err := json.Unmarshal(out.Bytes(), &ep); err != nil {
		t.Fatal(err)
	}
	if ep.AnalysisSource.Events != "sqlite" || ep.Summary.File.Attributed != 1 {
		t.Fatalf("episode=%+v", ep)
	}
	if err := episodeCommand(context.Background(), []string{"--exec-seq", "4"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "detection, not exec") {
		t.Fatalf("error=%v", err)
	}
}

func TestEpisodeMissingHomeDoesNotInitializeIt(t *testing.T) {
	home := filepath.Join(t.TempDir(), "absent")
	t.Setenv("LOGIRA_HOME", home)
	if err := episodeCommand(context.Background(), []string{"--exec-seq", "1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted missing run")
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatal("created home")
	}
}

func TestEpisodeBeyondQueryLimit(t *testing.T) {
	dir := episodeFixture(t)
	f, err := os.Create(filepath.Join(dir, "events.jsonl")) //nolint:gosec // Test fixture under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for i := int64(1); i <= 100001; i++ {
		if err := enc.Encode(storage.Event{RunID: episodeRunID, Seq: i, Type: storage.TypeFile, DataJSON: json.RawMessage(`{"op":"unknown"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	for _, e := range []storage.Event{{RunID: episodeRunID, Seq: 100002, Type: storage.TypeExec, DataJSON: json.RawMessage(`{"tid":10,"task_start_kernel_ns":10,"kernel_time_ns":20}`)}, {RunID: episodeRunID, Seq: 100003, Type: storage.TypeNet, DataJSON: json.RawMessage(`{"tid":10,"kernel_time_ns":30,"op":"send","bytes":12}`)}} {
		if err := enc.Encode(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := episodeCommand(context.Background(), []string{"--exec-seq", "100002", "--json"}, &out); err != nil {
		t.Fatal(err)
	}
	var ep episode.Episode
	if err := json.Unmarshal(out.Bytes(), &ep); err != nil {
		t.Fatal(err)
	}
	if ep.AnalysisSource.MaxSeq != 100003 || ep.Summary.File.Unattributable != 100001 || len(ep.NetworkEvents) != 1 || *ep.NetworkEvents[0].ExecSeq != 100002 {
		t.Fatalf("truncated episode: %+v", ep.Summary)
	}
}
