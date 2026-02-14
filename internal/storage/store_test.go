package storage

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/melonattacker/agentlogix/internal/model"
)

func TestStore_SQLiteAndJSONL(t *testing.T) {
	runDir := t.TempDir()
	runID := "20260214-000000-test"

	metaJSON := `{"run_id":"` + runID + `"}`
	s, err := Open(OpenParams{
		RunID:    runID,
		RunDir:   runDir,
		StartTS:  10,
		Command:  "echo hi",
		Tool:     "test",
		MetaJSON: metaJSON,
	})
	if err != nil {
		t.Fatal(err)
	}

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})
	seq1, err := s.AppendObserved(11, TypeExec, 123, 1, 1000, "exec echo hi", execDetail, EventRow{Exe: "/bin/echo"})
	if err != nil {
		t.Fatal(err)
	}
	if seq1 != 1 {
		t.Fatalf("seq1=%d", seq1)
	}

	fileDetail, _ := json.Marshal(model.FileDetail{Op: "modify", Path: "/repo/a.txt"})
	seq2, err := s.AppendObserved(12, TypeFile, 123, 1, 1000, "file modify /repo/a.txt", fileDetail, EventRow{Path: "/repo/a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if seq2 != 2 {
		t.Fatalf("seq2=%d", seq2)
	}

	_, err = s.AppendDetection(13, Detection{RuleID: "R1", Severity: "high", Message: "test", RelatedEventSeq: seq2}, seq2)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.SuspiciousCount(); got != 1 {
		t.Fatalf("suspicious=%d", got)
	}

	if err := s.Close(20, metaJSON); err != nil {
		t.Fatal(err)
	}

	sqlite, err := OpenSQLite(filepath.Join(runDir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer sqlite.Close()

	evs, err := sqlite.Query(QueryOptions{RunID: runID, Type: TypeFile, Path: "a.txt"})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected 1 file event, got %d", len(evs))
	}

	dets, err := sqlite.Query(QueryOptions{RunID: runID, Type: TypeDetection, Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(dets) != 1 {
		t.Fatalf("expected 1 detection, got %d", len(dets))
	}
}
