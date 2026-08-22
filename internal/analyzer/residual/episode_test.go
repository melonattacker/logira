package residual

import (
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestEpisodeSeparatesDirectMatchExecReplacementsAndDescendants(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "bash -c 'git status'", Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec bash -c git status", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "git status"}})},
		{RunID: "r", Seq: 3, TS: 12, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec fake git status", DataJSON: mustJSON(model.ExecDetail{Filename: "/tmp/bin/git", Argv: []string{"git", "status"}})},
		{RunID: "r", Seq: 4, TS: 13, Type: storage.TypeExec, PID: 21, PPID: 20, Summary: "exec touch marker", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/touch", Argv: []string{"touch", "/tmp/marker"}})},
		{RunID: "r", Seq: 5, TS: 14, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec real git status", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"/usr/bin/git", "status"}})},
		event(6, 15, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "bash -c 'git status'", Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || len(r.Episodes) != 1 {
		t.Fatalf("report=%+v", r)
	}
	episode := r.Episodes[0]
	if episode.DirectMatch.Seq != 2 || episode.Summary.Execs != 4 || episode.Summary.TransitiveExecs != 3 || episode.Summary.Wrappers != 0 {
		t.Fatalf("episode=%+v", episode)
	}
	wantRoles := []ExecMemberRole{ExecRoleDirectMatch, ExecRoleExecReplacement, ExecRoleDescendant, ExecRoleExecReplacement}
	for i, want := range wantRoles {
		if got := episode.ExecMembers[i].Role; got != want {
			t.Fatalf("member[%d] role=%s, want %s; episode=%+v", i, got, want, episode)
		}
	}
	if r.Counts[ObservedNotReported] != 0 || r.Counts[ReportedNotObserved] != 0 {
		t.Fatalf("episode inspection changed residual classifications: %+v", r.Counts)
	}
}

func TestEpisodePreservesWrapperAncestorRole(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		{RunID: "r", Seq: 3, TS: 8, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec bwrap", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/bwrap", Argv: []string{"bwrap", "--", "bash", "-c", "echo hi"}})},
		{RunID: "r", Seq: 4, TS: 9, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec bash", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "echo hi"}})},
		event(5, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "bash -c 'echo hi'", Status: "completed"}),
	}

	r := Analyze(m, events)
	if len(r.Episodes) != 1 || len(r.Episodes[0].ExecMembers) != 2 {
		t.Fatalf("report=%+v", r)
	}
	if r.Episodes[0].ExecMembers[0].Role != ExecRoleWrapper || r.Episodes[0].ExecMembers[1].Role != ExecRoleDirectMatch {
		t.Fatalf("wrapper roles=%+v", r.Episodes[0].ExecMembers)
	}
	if !r.Episodes[0].AncestryComplete {
		t.Fatalf("observed launcher ancestry reported incomplete: %+v", r.Episodes[0])
	}
	if r.Episodes[0].Summary.Wrappers != 1 || r.Episodes[0].Summary.TransitiveExecs != 0 {
		t.Fatalf("wrapper was mislabeled as a transitive effect: %+v", r.Episodes[0].Summary)
	}
}

func TestEpisodeRecordsIncompleteDirectMatchAncestry(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "echo hi", Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 999, Summary: "exec echo hi", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})},
		event(3, 12, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "echo hi", Status: "completed"}),
	}

	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || len(r.Episodes) != 1 {
		t.Fatalf("report=%+v", r)
	}
	episode := r.Episodes[0]
	if episode.AncestryComplete || len(episode.AttributionIssues) == 0 || !strings.Contains(episode.AttributionIssues[0], "parent exec") {
		t.Fatalf("missing ancestry uncertainty: %+v", episode)
	}
}

func TestEpisodeAttributesFileAndNetworkEffectsToExecGeneration(t *testing.T) {
	m := completeMeta()
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "in_progress"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec make test", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/make", Argv: []string{"make", "test"}})},
		{RunID: "r", Seq: 3, TS: 12, Type: storage.TypeExec, PID: 21, PPID: 20, Summary: "exec helper", DataJSON: mustJSON(model.ExecDetail{Filename: "/tmp/helper", Argv: []string{"helper"}})},
		{RunID: "r", Seq: 4, TS: 13, Type: storage.TypeFile, Summary: "file create /tmp/marker", DataJSON: mustJSON(model.FileDetail{PID: 21, Op: "create", Path: "/tmp/marker"})},
		{RunID: "r", Seq: 5, TS: 14, Type: storage.TypeNet, PID: 21, Summary: "net connect 127.0.0.1:12345", DataJSON: mustJSON(model.NetDetail{Op: "connect", Proto: "tcp", DstIP: "127.0.0.1", DstPort: 12345})},
		{RunID: "r", Seq: 6, TS: 14, Type: storage.TypeFile, PID: 999, Summary: "file create /tmp/unrelated", DataJSON: mustJSON(model.FileDetail{Op: "create", Path: "/tmp/unrelated"})},
		{RunID: "r", Seq: 7, TS: 14, Type: storage.TypeNet, PID: 999, Summary: "net connect 127.0.0.1:9", DataJSON: mustJSON(model.NetDetail{Op: "connect", Proto: "tcp", DstIP: "127.0.0.1", DstPort: 9})},
		event(8, 15, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "completed"}),
	}

	r := Analyze(m, events)
	if len(r.Episodes) != 1 {
		t.Fatalf("report=%+v", r)
	}
	episode := r.Episodes[0]
	if len(episode.FileEffects) != 1 || episode.FileEffects[0].ProcessExecSeq != 3 || episode.FileEffects[0].Path != "/tmp/marker" {
		t.Fatalf("file effects=%+v", episode.FileEffects)
	}
	if len(episode.NetworkEffects) != 1 || episode.NetworkEffects[0].ProcessExecSeq != 3 || episode.NetworkEffects[0].DstPort != 12345 {
		t.Fatalf("network effects=%+v", episode.NetworkEffects)
	}
	if episode.Summary.Files != 1 || episode.Summary.Networks != 1 {
		t.Fatalf("summary=%+v", episode.Summary)
	}
}

func TestEpisodeRecordsPartialProcessCaptureWithoutChangingMatch(t *testing.T) {
	m := completeMeta()
	m.Coverage.Process.Capture = "partial"
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "echo hi", Status: "completed"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 0, Summary: "exec echo hi", DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}})},
	}
	r := Analyze(m, events)
	if r.Counts[Matched] != 1 || r.Episodes[0].ProcessCapture != "partial" || len(r.Episodes[0].AttributionIssues) == 0 {
		t.Fatalf("report=%+v", r)
	}
}
