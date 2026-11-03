package detect

import (
	"encoding/json"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestCredentialOpenAccessModes(t *testing.T) {
	e := mustEngine(t, "/home/u")
	paths := map[string]string{"/home/u/.ssh/id_ed25519": "F020", "/home/u/.aws/credentials": "F021", "/home/u/.kube/config": "F022", "/home/u/.docker/config.json": "F023", "/home/u/.netrc": "F024"}
	for path, id := range paths {
		for _, tc := range []struct {
			mode  string
			flags uint32
			want  bool
		}{
			{"read_only", 0, true}, {"write_only", 1, false}, {"read_write", 2, true}, {"path_only", 0x200000, false}, {"unknown", 3, false},
		} {
			t.Run(id+"/"+tc.mode, func(t *testing.T) {
				d := model.FileDetail{Op: "open", Path: path, Syscall: "openat", Correlation: "complete", Flags: tc.flags, ReturnValue: 3, AccessMode: tc.mode}
				b, _ := json.Marshal(d)
				found := false
				for _, det := range e.Evaluate(storage.TypeFile, b) {
					if det.RuleID == id {
						found = true
					}
				}
				if found != tc.want {
					t.Fatalf("detections for %+v: got %v want %v", d, found, tc.want)
				}
				if got := e.ShouldRecordFile(d); got != tc.want {
					t.Fatalf("retention=%v want %v", got, tc.want)
				}
			})
		}
	}
	// Legacy observations remain readable and retain their historical rule behavior.
	b := json.RawMessage(`{"op":"open","path":"/home/u/.netrc"}`)
	if len(e.Evaluate(storage.TypeFile, b)) == 0 {
		t.Fatal("legacy open no longer matches")
	}
}

func TestAmbiguousTruncatingOpenMatchesWriteRules(t *testing.T) {
	e := mustEngine(t, "/home/u")
	for _, path := range []string{"/home/u/.ssh/authorized_keys", "/etc/cron.d/task", "/etc/systemd/system/task.service"} {
		for _, syscall := range []string{"openat", "openat2"} {
			for _, tc := range []struct {
				name        string
				flags       uint32
				ret         int64
				correlation string
				want        bool
			}{
				{"truncate write-only", 0x40 | 0x200 | 1, 3, "complete", true},
				{"truncate read-write", 0x40 | 0x200 | 2, 3, "complete", true},
				{"create ambiguity only", 0x40 | 1, 3, "complete", false},
				{"failed", 0x40 | 0x200 | 1, -1, "complete", false},
				{"uncorrelated", 0x40 | 0x200 | 1, 3, "incomplete", false},
				{"path only", 0x40 | 0x200 | 0x200000, 3, "complete", false},
			} {
				t.Run(path+"/"+syscall+"/"+tc.name, func(t *testing.T) {
					d := model.FileDetail{Op: "create_or_open", Path: path, Syscall: syscall, Correlation: tc.correlation, Flags: tc.flags, ReturnValue: tc.ret}
					raw, _ := json.Marshal(d)
					got := e.Evaluate(storage.TypeFile, raw)
					if (len(got) > 0) != tc.want {
						t.Fatalf("detections=%+v want match=%v", got, tc.want)
					}
					if d.Op != "create_or_open" {
						t.Fatal("observation rewritten as creation")
					}
				})
			}
		}
	}
	e, err := NewEngineWithRules("/home/u", []Rule{{ID: "create-only", Type: storage.TypeFile, Severity: "high", Message: "created", When: WhenClause{File: &FileWhen{Prefix: "/home/u/.ssh", OpIn: []string{"create"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	raw := json.RawMessage(`{"op":"create_or_open","path":"/home/u/.ssh/authorized_keys","flags":577,"syscall":"openat","correlation":"complete","return_value":3}`)
	if got := e.Evaluate(storage.TypeFile, raw); len(got) != 0 {
		t.Fatalf("claimed creation: %+v", got)
	}
}
