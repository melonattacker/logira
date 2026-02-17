//go:build linux

package cli

import (
	"testing"

	"github.com/melonattacker/logira/internal/ipc"
)

func TestDecideReady_OK(t *testing.T) {
	out := statusJSON{}
	out.CgroupV2.Enabled = true
	st := ipc.StatusResponse{UID: 0, EnableExec: true, EnableFile: true, EnableNet: true}

	ready, reasons := decideReady(out, st, statusRequired{Exec: true, File: true, Net: true})
	if !ready {
		t.Fatalf("expected ready=true, got false reasons=%v", reasons)
	}
	if len(reasons) != 0 {
		t.Fatalf("expected no reasons, got %v", reasons)
	}
}

func TestDecideReady_NotRoot(t *testing.T) {
	out := statusJSON{}
	out.CgroupV2.Enabled = true
	st := ipc.StatusResponse{UID: 1000, EnableExec: true, EnableFile: true, EnableNet: true}

	ready, reasons := decideReady(out, st, statusRequired{Exec: true, File: true, Net: true})
	if ready {
		t.Fatalf("expected ready=false")
	}
	if len(reasons) == 0 || reasons[0] != "daemon_not_root" {
		t.Fatalf("expected daemon_not_root first, got %v", reasons)
	}
}

func TestDecideReady_ProbeRequirement(t *testing.T) {
	out := statusJSON{}
	out.CgroupV2.Enabled = true
	st := ipc.StatusResponse{UID: 0, EnableExec: true, EnableFile: true, EnableNet: false}

	ready, reasons := decideReady(out, st, statusRequired{Exec: true, File: true, Net: true})
	if ready {
		t.Fatalf("expected ready=false")
	}
	if !contains(reasons, "probe_net_disabled_in_daemon") {
		t.Fatalf("expected probe_net_disabled_in_daemon in reasons, got %v", reasons)
	}

	ready, reasons = decideReady(out, st, statusRequired{Exec: true, File: true, Net: false})
	if !ready {
		t.Fatalf("expected ready=true when net not required, got false reasons=%v", reasons)
	}
}

func TestDecideReady_CgroupRequired(t *testing.T) {
	out := statusJSON{}
	out.CgroupV2.Enabled = false
	st := ipc.StatusResponse{UID: 0, EnableExec: true, EnableFile: true, EnableNet: true}

	ready, reasons := decideReady(out, st, statusRequired{Exec: true, File: true, Net: true})
	if ready {
		t.Fatalf("expected ready=false")
	}
	if !contains(reasons, "cgroup_v2_disabled") {
		t.Fatalf("expected cgroup_v2_disabled in reasons, got %v", reasons)
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
