package storage

import (
	"path/filepath"
	"testing"
)

func TestSummaryQueries(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenSQLite(filepath.Join(dir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	runID := "20260219-123000-test"
	if err := db.InsertRun(RunRow{
		ID:              runID,
		StartTS:         10,
		EndTS:           20,
		Command:         "bash -lc true",
		Tool:            "bash",
		SuspiciousCount: 1,
		MetaJSON:        "{}",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertEvent(EventRow{
		RunID:    runID,
		Seq:      1,
		TS:       11,
		Type:     "net",
		PID:      10,
		Summary:  "net connect 1.2.3.4:443",
		DataJSON: `{"op":"connect","dst_ip":"1.2.3.4","dst_port":443}`,
		DstIP:    "1.2.3.4",
		DstPort:  443,
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertEvent(EventRow{
		RunID:    runID,
		Seq:      2,
		TS:       12,
		Type:     "file",
		PID:      10,
		Summary:  "file modify a.txt",
		DataJSON: `{"op":"modify","path":"a.txt"}`,
		Path:     "a.txt",
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.InsertDetection(DetectionRow{
		RunID:      runID,
		Seq:        3,
		TS:         13,
		RuleID:     "R1",
		Severity:   "low",
		Message:    "test detection",
		RelatedSeq: 1,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := db.GetRunRow(runID); err != nil {
		t.Fatalf("GetRunRow: %v", err)
	}
	evtCounts, err := db.CountEventsByType(runID)
	if err != nil {
		t.Fatal(err)
	}
	if evtCounts[TypeNet] != 1 || evtCounts[TypeFile] != 1 {
		t.Fatalf("unexpected event counts: %#v", evtCounts)
	}
	sevCounts, err := db.CountDetectionsBySeverity(runID)
	if err != nil {
		t.Fatal(err)
	}
	if sevCounts["low"] != 1 {
		t.Fatalf("unexpected severity counts: %#v", sevCounts)
	}
	grouped, err := db.ListGroupedDetections(runID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(grouped) != 1 || grouped[0].Count != 1 {
		t.Fatalf("unexpected grouped rows: %#v", grouped)
	}
	withRelated, err := db.ListDetectionsWithRelated(runID, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(withRelated) != 1 || withRelated[0].RelatedSeq != 1 || !withRelated[0].RelatedEventSeen {
		t.Fatalf("unexpected related rows: %#v", withRelated)
	}
	if _, err := db.GetDetectionBySeq(runID, 3); err != nil {
		t.Fatalf("GetDetectionBySeq: %v", err)
	}
	if _, err := db.GetEventBySeq(runID, 1); err != nil {
		t.Fatalf("GetEventBySeq: %v", err)
	}
}
