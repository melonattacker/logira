package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/storage"
)

func TestLoadRunEndSummaryRiskLevels(t *testing.T) {
	tests := []struct {
		name       string
		severities []string
		wantRisk   string
	}{
		{name: "no detections", wantRisk: "NONE"},
		{name: "info only", severities: []string{"info"}, wantRisk: "LOW"},
		{name: "low only", severities: []string{"low"}, wantRisk: "LOW"},
		{name: "medium only", severities: []string{"medium"}, wantRisk: "MEDIUM"},
		{name: "high wins", severities: []string{"low", "medium", "high"}, wantRisk: "HIGH"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runID, runDir := seedRunSummaryDB(t, tt.severities...)

			s, err := loadRunEndSummary(runID, runDir, 0)
			if err != nil {
				t.Fatal(err)
			}
			if s.Risk != tt.wantRisk {
				t.Fatalf("risk=%q want %q", s.Risk, tt.wantRisk)
			}
			if s.EventCounts[storage.TypeExec] != 1 || s.EventCounts[storage.TypeFile] != 1 || s.EventCounts[storage.TypeNet] != 1 {
				t.Fatalf("unexpected event counts: %#v", s.EventCounts)
			}
			if s.SeverityCounts["info"]+s.SeverityCounts["low"]+s.SeverityCounts["medium"]+s.SeverityCounts["high"] != len(tt.severities) {
				t.Fatalf("unexpected severity counts: %#v", s.SeverityCounts)
			}
		})
	}
}

func TestRenderRunEndSummaryModes(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"logira"}
	t.Cleanup(func() {
		os.Args = oldArgs
	})

	s := runEndSummary{
		RunID:    "20260507-143022-claude",
		Duration: "2s",
		ExitCode: 42,
		EventCounts: map[storage.EventType]int{
			storage.TypeExec: 3,
			storage.TypeFile: 4,
			storage.TypeNet:  5,
		},
		SeverityCounts: map[string]int{"high": 1, "medium": 2, "low": 3, "info": 4},
		Risk:           "HIGH",
		TopDetections: []storage.GroupedDetection{
			{Severity: "high", RuleID: "F021", Message: "read aws credentials/config", Count: 2},
		},
	}

	var auto bytes.Buffer
	if err := renderRunEndSummary(&auto, runSummaryModeAuto, s); err != nil {
		t.Fatal(err)
	}
	autoOut := auto.String()
	for _, want := range []string{
		"[logira] run 20260507-143022-claude finished in 2s, exit=42",
		"events:      3 exec, 4 file, 5 net",
		"detections:  1 high, 2 medium, 3 low, 4 info",
		"risk:        HIGH",
		"HIGH   F021",
		"logira view 20260507-143022-claude",
		"logira explain 20260507-143022-claude --show-related",
	} {
		if !strings.Contains(autoOut, want) {
			t.Fatalf("auto output missing %q:\n%s", want, autoOut)
		}
	}

	var detections bytes.Buffer
	if err := renderRunEndSummary(&detections, runSummaryModeDetections, s); err != nil {
		t.Fatal(err)
	}
	detOut := detections.String()
	if strings.Contains(detOut, "events:") {
		t.Fatalf("detections mode should omit events line:\n%s", detOut)
	}
	if !strings.Contains(detOut, "exit=42") || !strings.Contains(detOut, "risk:        HIGH") {
		t.Fatalf("detections output missing exit/risk:\n%s", detOut)
	}

	var off bytes.Buffer
	if err := renderRunEndSummary(&off, runSummaryModeOff, s); err != nil {
		t.Fatal(err)
	}
	if off.Len() != 0 {
		t.Fatalf("off mode wrote output: %q", off.String())
	}
}

func seedRunSummaryDB(t *testing.T, severities ...string) (string, string) {
	t.Helper()
	runID := "20260507-143022-test"
	runDir := t.TempDir()
	db, err := storage.OpenSQLite(filepath.Join(runDir, "index.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = db.Close()
	}()

	if err := db.InsertRun(storage.RunRow{
		ID:      runID,
		StartTS: 1_000_000_000,
		EndTS:   3_000_000_000,
		Command: "bash -lc true",
		Tool:    "bash",
	}); err != nil {
		t.Fatal(err)
	}
	events := []storage.EventRow{
		{RunID: runID, Seq: 1, TS: 1_100_000_000, Type: string(storage.TypeExec), Summary: "exec bash", DataJSON: `{"filename":"/usr/bin/bash"}`},
		{RunID: runID, Seq: 2, TS: 1_200_000_000, Type: string(storage.TypeFile), Summary: "file modify x.txt", DataJSON: `{"op":"modify","path":"x.txt"}`, Path: "x.txt"},
		{RunID: runID, Seq: 3, TS: 1_300_000_000, Type: string(storage.TypeNet), Summary: "net connect 1.2.3.4:443", DataJSON: `{"op":"connect","dst_ip":"1.2.3.4","dst_port":443}`, DstIP: "1.2.3.4", DstPort: 443},
	}
	for _, ev := range events {
		if err := db.InsertEvent(ev); err != nil {
			t.Fatal(err)
		}
	}
	for i, sev := range severities {
		if err := db.InsertDetection(storage.DetectionRow{
			RunID:      runID,
			Seq:        int64(4 + i),
			TS:         int64(1_400_000_000 + i),
			RuleID:     "R001",
			Severity:   sev,
			Message:    sev + " detection",
			RelatedSeq: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return runID, runDir
}
