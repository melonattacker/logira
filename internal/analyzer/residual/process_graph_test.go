package residual

import (
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestForkOnlyTaskChainConnectsExecutionEpisode(t *testing.T) {
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "in_progress"}),
		processEvent(2, 11, model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTGID: 10, ChildTID: 20, TaskStartKernelNS: 200, KernelTimeNS: 200}),
		{RunID: "r", Seq: 3, TS: 12, Type: storage.TypeExec, PID: 20, Summary: "exec make test", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/make", Argv: []string{"make", "test"}, TID: 20, TGID: 20, TaskStartKernelNS: 200, KernelTimeNS: 210})},
		processEvent(4, 13, model.ProcessDetail{Kind: "fork", ParentTID: 20, ParentTGID: 20, ParentTaskStartKernelNS: 200, ChildTID: 21, TaskStartKernelNS: 300, KernelTimeNS: 300}),
		processEvent(5, 14, model.ProcessDetail{Kind: "fork", ParentTID: 21, ParentTGID: 21, ParentTaskStartKernelNS: 300, ChildTID: 22, TaskStartKernelNS: 400, KernelTimeNS: 400}),
		{RunID: "r", Seq: 6, TS: 15, Type: storage.TypeExec, PID: 22, PPID: 999, Summary: "exec child", DataJSON: mustJSON(model.ExecDetail{Filename: "/tmp/child", Argv: []string{"child"}, TID: 22, TGID: 22, TaskStartKernelNS: 400, KernelTimeNS: 410})},
		event(7, 16, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "completed"}),
	}

	r := Analyze(completeMeta(), events)
	if len(r.Episodes) != 1 {
		t.Fatalf("report=%+v", r)
	}
	episode := r.Episodes[0]
	if len(episode.ExecMembers) != 2 || episode.ExecMembers[1].ParentExecSeq != 3 {
		t.Fatalf("fork-only ancestry did not connect descendant exec: %+v", episode.ExecMembers)
	}
	if episode.Summary.Processes != 3 {
		t.Fatalf("process members=%+v summary=%+v", episode.ProcessMembers, episode.Summary)
	}
}

func TestDeThreadExecRekeysTaskIdentityWithoutMergingLeader(t *testing.T) {
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/unrelated/leader", TID: 20, TGID: 20, TaskStartKernelNS: 50, KernelTimeNS: 50})},
		processEvent(2, 2, model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTGID: 10, ChildTID: 21, TaskStartKernelNS: 100, KernelTimeNS: 100}),
		{RunID: "r", Seq: 3, TS: 3, Type: storage.TypeExec, PID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "echo hi"}, TID: 21, TGID: 20, OldPID: 21, TaskStartKernelNS: 100, KernelTimeNS: 110})},
		processEvent(4, 4, model.ProcessDetail{Kind: "exec_rekey", TID: 20, TGID: 20, OldPID: 21, TaskStartKernelNS: 100, KernelTimeNS: 120}),
		{RunID: "r", Seq: 5, TS: 5, Type: storage.TypeExec, PID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/echo", Argv: []string{"echo", "hi"}, TID: 20, TGID: 20, OldPID: 21, TaskStartKernelNS: 100, KernelTimeNS: 120})},
	}

	execs := collectExecs(events, collectProcessGraph(events))
	if len(execs) != 3 {
		t.Fatalf("execs=%+v", execs)
	}
	if execs[2].parent != 1 || execs[2].generation != 2 {
		t.Fatalf("de-thread exec linked to wrong identity: parent=%d generation=%d", execs[2].parent, execs[2].generation)
	}
}

func TestPIDReuseCreatesNewTaskInstance(t *testing.T) {
	events := []storage.Event{
		processEvent(1, 1, model.ProcessDetail{Kind: "fork", ParentTID: 10, ChildTID: 20, TaskStartKernelNS: 100, KernelTimeNS: 100}),
		{RunID: "r", Seq: 2, TS: 2, Type: storage.TypeExec, PID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/one", TID: 20, TGID: 20, TaskStartKernelNS: 100, KernelTimeNS: 110})},
		processEvent(3, 3, model.ProcessDetail{Kind: "exit", TID: 20, TGID: 20, TaskStartKernelNS: 100, KernelTimeNS: 120, GroupDead: "unknown"}),
		processEvent(4, 4, model.ProcessDetail{Kind: "fork", ParentTID: 10, ChildTID: 20, TaskStartKernelNS: 200, KernelTimeNS: 200}),
		{RunID: "r", Seq: 5, TS: 5, Type: storage.TypeExec, PID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/bin/two", TID: 20, TGID: 20, TaskStartKernelNS: 200, KernelTimeNS: 210})},
	}

	execs := collectExecs(events, collectProcessGraph(events))
	if execs[0].generation != 1 || execs[1].generation != 1 || execs[1].parent >= 0 {
		t.Fatalf("PID reuse inherited old generation: %+v", execs)
	}
}

func TestThreadCloneUsesObservedTGID(t *testing.T) {
	events := []storage.Event{processEvent(1, 1, model.ProcessDetail{
		Kind: "fork", ParentTID: 10, ParentTGID: 10, ChildTID: 11, ChildTGID: 10,
		TaskStartKernelNS: 100, KernelTimeNS: 100, CloneKind: "thread_clone",
	})}
	g := collectProcessGraph(events)
	node := g.nodes[taskIdentity{tid: 11, start: 100}]
	if node == nil || node.cloneKind != "thread_clone" {
		t.Fatalf("node=%+v", node)
	}
}

func TestVersion4RunFallsBackToExecPPIDAncestry(t *testing.T) {
	m := completeMeta()
	m.Version = 4
	events := []storage.Event{
		event(1, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: "make test", Status: "completed"}),
		{RunID: "r", Seq: 2, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/make", Argv: []string{"make", "test"}})},
		{RunID: "r", Seq: 3, TS: 12, Type: storage.TypeExec, PID: 21, PPID: 20, DataJSON: mustJSON(model.ExecDetail{Filename: "/tmp/child", Argv: []string{"child"}})},
	}
	r := Analyze(m, events)
	if len(r.Episodes) != 1 || len(r.Episodes[0].ExecMembers) != 2 {
		t.Fatalf("version 4 fallback report=%+v", r)
	}
}

func processEvent(seq, ts int64, detail model.ProcessDetail) storage.Event {
	return storage.Event{RunID: "r", Seq: seq, TS: ts, Type: storage.TypeProcess, DataJSON: mustJSON(detail)}
}
