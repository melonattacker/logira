package processgraph

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func event(seq int64, typ storage.EventType, detail any) storage.Event {
	b, err := json.Marshal(detail)
	if err != nil {
		panic(err)
	}
	return storage.Event{RunID: "r", Seq: seq, TS: 1000 - seq, Type: typ, DataJSON: b}
}
func fork(seq int64, parent, child int, birth, parentBirth uint64) storage.Event {
	return event(seq, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: parent, ParentTaskStartKernelNS: parentBirth, ChildTID: child, TaskStartKernelNS: birth, KernelTimeNS: birth + 1})
}
func execEvent(seq int64, tid int, birth, at uint64) storage.Event {
	return event(seq, storage.TypeExec, model.ExecDetail{Filename: "/bin/test", TID: tid, TGID: tid, TaskStartKernelNS: birth, KernelTimeNS: at})
}
func exitEvent(seq int64, tid int, birth, at uint64) storage.Event {
	return event(seq, storage.TypeProcess, model.ProcessDetail{Kind: "exit", TID: tid, TGID: tid, TaskStartKernelNS: birth, KernelTimeNS: at})
}
func build(t *testing.T, evs ...storage.Event) *Graph {
	t.Helper()
	g, err := Build("r", evs)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestForkExecExitAndForkOnly(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), fork(2, 10, 11, 30, 10), fork(3, 11, 12, 40, 30), execEvent(4, 12, 40, 50), exitEvent(5, 12, 40, 60))
	if len(g.Tasks) != 3 || len(g.Forks) != 2 {
		t.Fatalf("tasks=%+v forks=%+v", g.Tasks, g.Forks)
	}
	for _, f := range g.Forks {
		if f.ParentTaskID == nil {
			t.Fatalf("unresolved fork %+v", f)
		}
	}
	middle := g.Task(g.Forks[0].ChildTaskID)
	if len(middle.ExecSeqs) != 0 || g.ExecAt(middle.ID, 35) != nil {
		t.Fatal("invented fork-only exec")
	}
	if got := g.Resolve(Identity{TID: 12}, 55); got.TaskID != g.Execs[4].TaskID || got.Basis != "tid_kernel_interval" {
		t.Fatalf("resolution=%+v", got)
	}
	if got := g.Resolve(Identity{TID: 12}, 61); got.TaskID != "" {
		t.Fatalf("resolved after exit: %+v", got)
	}
}

func TestMultipleExecGenerationsAndEqualBoundary(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), execEvent(2, 10, 10, 40), execEvent(3, 10, 10, 60))
	if len(g.Tasks) != 1 || *g.Execs[3].Generation != 3 || *g.Execs[3].PreviousExecSeq != 2 {
		t.Fatalf("execs=%+v", g.Execs)
	}
	for _, tc := range []struct {
		at  uint64
		seq int64
	}{{19, 0}, {20, 0}, {30, 1}, {40, 0}, {50, 2}, {70, 3}} {
		got := g.ExecAt(g.Tasks[0].ID, tc.at)
		if tc.seq == 0 {
			if got != nil {
				t.Fatalf("at=%d exec=%+v", tc.at, got)
			}
		} else if got == nil || got.Event.Seq != tc.seq {
			t.Fatalf("at=%d exec=%+v", tc.at, got)
		}
	}
}

func TestNonLeaderRekeyPreservesTaskNotLeader(t *testing.T) {
	evs := []storage.Event{execEvent(1, 20, 10, 20), fork(2, 20, 21, 30, 10),
		event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", TID: 20, TGID: 20, OldPID: 21, TaskStartKernelNS: 30, KernelTimeNS: 51}),
		event(4, storage.TypeExec, model.ExecDetail{Filename: "/bin/new", TID: 20, TGID: 20, OldPID: 21, TaskStartKernelNS: 30, KernelTimeNS: 50}), exitEvent(5, 20, 30, 70)}
	g := build(t, evs...)
	if len(g.Tasks) != 2 || g.Execs[1].TaskID == g.Execs[4].TaskID {
		t.Fatalf("merged leader: %+v", g.Tasks)
	}
	task := g.Task(g.Execs[4].TaskID)
	if task.Conflicted || len(task.Identities) != 2 || len(task.RekeySeqs) != 1 {
		t.Fatalf("rekey task=%+v", task)
	}
	for _, tc := range []struct {
		tid  int
		at   uint64
		task string
	}{{21, 40, task.ID}, {20, 60, task.ID}, {20, 25, g.Execs[1].TaskID}} {
		if got := g.Resolve(Identity{TID: tc.tid}, tc.at); got.TaskID != tc.task {
			t.Fatalf("%+v: %+v", tc, got)
		}
	}
	if g.Resolve(Identity{TID: 21}, 60).TaskID != "" {
		t.Fatal("old alias survived transition")
	}
}

func TestExecOldPIDWithoutLifecycleAndUnpairedRekey(t *testing.T) {
	base := []storage.Event{fork(1, 1, 21, 10, 0), event(2, storage.TypeExec, model.ExecDetail{TID: 20, TGID: 20, OldPID: 21, TaskStartKernelNS: 10, KernelTimeNS: 30})}
	g := build(t, base...)
	if len(g.Tasks) != 1 || len(g.Tasks[0].RekeySeqs) != 0 {
		t.Fatal("lost transition or fabricated rekey")
	}
	base = append(base, event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", TID: 19, TGID: 19, OldPID: 20, TaskStartKernelNS: 10, KernelTimeNS: 50}))
	g = build(t, base...)
	if len(g.Execs) != 1 || g.ExecAt(g.Tasks[0].ID, 60) != nil {
		t.Fatal("rekey invented or retained executable generation")
	}
}

func TestPIDReuseWithoutExit(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), fork(2, 1, 10, 100, 0), execEvent(3, 10, 100, 110))
	if len(g.Tasks) != 2 || *g.Execs[3].Generation != 1 {
		t.Fatal("PID reuse merged")
	}
	for _, tc := range []struct {
		at  uint64
		seq int64
	}{{30, 1}, {120, 3}} {
		if got := g.Resolve(Identity{TID: 10}, tc.at); got.TaskID != g.Execs[tc.seq].TaskID {
			t.Fatalf("resolution=%+v", got)
		}
	}
	if len(g.Task(g.Execs[1].TaskID).ExitSeqs) != 0 {
		t.Fatal("fabricated exit")
	}
	if got := g.Resolve(Identity{TID: 10}, 0); got.TaskID != "" || len(got.Candidates) != 2 {
		t.Fatalf("ambiguous reuse resolved: %+v", got)
	}
}

func TestMissingParentAndImpossibleParent(t *testing.T) {
	for _, evs := range [][]storage.Event{
		{fork(1, 99, 20, 100, 0), execEvent(2, 20, 100, 110)},
		{execEvent(1, 99, 200, 210), fork(2, 99, 20, 100, 200)},
		{execEvent(1, 99, 10, 20), exitEvent(2, 99, 10, 30), fork(3, 99, 20, 100, 10)},
	} {
		g := build(t, evs...)
		if g.Forks[0].ParentTaskID != nil {
			t.Fatalf("fabricated parent: %+v", g.Forks[0])
		}
	}
}

func TestLegacyAndUnknownBirthStaySeparate(t *testing.T) {
	a := event(1, storage.TypeExec, model.ExecDetail{Filename: "/bin/a"})
	a.PID = 20
	b := event(2, storage.TypeExec, model.ExecDetail{Filename: "/bin/b"})
	b.PID = 20
	b.PPID = 20
	g := build(t, a, b)
	if len(g.Tasks) != 2 || len(g.Forks) != 0 || g.Resolve(Identity{TID: 20}, 0).TaskID != "" {
		t.Fatal("legacy identity fabricated")
	}
	first := event(3, storage.TypeExec, model.ExecDetail{TID: 30, FirstObservedKernelNS: 100, KernelTimeNS: 110})
	second := event(4, storage.TypeExec, model.ExecDetail{TID: 30, FirstObservedKernelNS: 100, KernelTimeNS: 120})
	g = build(t, first, second)
	if len(g.Tasks) != 1 || g.Tasks[0].Identities[0].Birth != 0 || *g.Execs[4].Generation != 2 {
		t.Fatal("first observation confused with birth")
	}
}

func TestWeakForkIdentityAndThreadSeparation(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), event(2, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: 10, ParentTaskStartKernelNS: 10, ChildTID: 11, ChildTGID: 10, KernelTimeNS: 30, CloneKind: "thread_clone"}), event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exit", TID: 11, TGID: 10, KernelTimeNS: 50}))
	if len(g.Tasks) != 2 || g.Forks[0].CloneKind != "thread_clone" || g.Forks[0].ParentTaskID == nil {
		t.Fatalf("graph=%+v", g)
	}
	if r := g.Resolve(Identity{TID: 11, TGID: 10}, 40); r.TaskID != g.Forks[0].ChildTaskID {
		t.Fatalf("thread resolution=%+v", r)
	}
	if len(g.Task(g.Forks[0].ChildTaskID).ExitSeqs) != 1 {
		t.Fatal("missing weak exit")
	}
}

func TestInputPermutationDeterminism(t *testing.T) {
	evs := []storage.Event{execEvent(1, 10, 10, 20), fork(2, 10, 11, 30, 10), execEvent(3, 11, 30, 40), exitEvent(4, 11, 30, 50)}
	want := build(t, evs...)
	rng := rand.New(rand.NewSource(7)) //nolint:gosec // Reproducible input permutations, not security randomness.
	for n := 0; n < 20; n++ {
		rng.Shuffle(len(evs), func(i, j int) { evs[i], evs[j] = evs[j], evs[i] })
		got := build(t, evs...)
		if !reflect.DeepEqual(want, got) {
			t.Fatal("input order changed graph")
		}
	}
}

func TestMalformedDataAndAmbiguousExecOrder(t *testing.T) {
	for _, evs := range [][]storage.Event{{event(1, storage.TypeExec, nil)}, {event(1, storage.TypeProcess, model.ProcessDetail{Kind: "future"})}, {execEvent(1, 1, 1, 2), execEvent(1, 2, 2, 3)}} {
		if _, err := Build("r", evs); err == nil {
			t.Fatal("accepted malformed/unsupported data")
		}
	}
	g := build(t, execEvent(1, 10, 10, 20), execEvent(2, 10, 10, 20))
	if g.Execs[1].Generation != nil || g.ExecAt(g.Tasks[0].ID, 30) != nil {
		t.Fatal("invented exec order")
	}
}

func TestLateWeakExitInvalidatesEarlierLinkedExec(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 100), fork(2, 10, 11, 110, 10), event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exit", TID: 10, KernelTimeNS: 50}))
	if !g.Task(g.Execs[1].TaskID).Conflicted || g.Forks[0].ParentTaskID != nil || g.Resolve(Identity{TID: 10, Birth: 10}, 120).TaskID != "" {
		t.Fatal("conflicting lifetime was treated as reliable")
	}
}

func TestConflictingTGIDAndForksStayUnresolved(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), fork(2, 10, 11, 30, 10), event(3, storage.TypeExec, model.ExecDetail{TID: 10, TGID: 99, TaskStartKernelNS: 10, KernelTimeNS: 40}))
	if !g.Task(g.Execs[1].TaskID).Conflicted || g.Forks[0].ParentTaskID != nil {
		t.Fatal("conflicting group identity accepted")
	}
	g = build(t, execEvent(1, 10, 10, 20), execEvent(2, 12, 15, 25), fork(3, 10, 11, 30, 10), fork(4, 12, 11, 30, 15))
	for _, f := range g.Forks {
		if f.ParentTaskID != nil {
			t.Fatal("selected an arbitrary fork parent")
		}
	}
}

func TestRekeyWithFirstObservationDoesNotInventBirth(t *testing.T) {
	g := build(t, event(1, storage.TypeExec, model.ExecDetail{TID: 11, TGID: 10, FirstObservedKernelNS: 10, KernelTimeNS: 20}), event(2, storage.TypeExec, model.ExecDetail{TID: 10, TGID: 10, OldPID: 11, FirstObservedKernelNS: 10, KernelTimeNS: 30}))
	if len(g.Tasks) != 1 || *g.Execs[2].Generation != 2 || g.Tasks[0].Identities[0].Birth != 0 {
		t.Fatal("lost rekey continuity or fabricated birth")
	}
}

func TestUnidentifiedNonLeaderTransitionNeverSelectsDisplacedLeader(t *testing.T) {
	for _, transition := range []storage.Event{
		event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", TID: 10, TGID: 10, OldPID: 11, KernelTimeNS: 50}),
		event(3, storage.TypeExec, model.ExecDetail{TID: 10, TGID: 10, OldPID: 11, KernelTimeNS: 50}),
		event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", TID: 10, TGID: 10, OldPID: 11}),
	} {
		g := build(t, execEvent(1, 10, 10, 20), fork(2, 10, 11, 30, 10), transition)
		if len(g.Tasks) != 3 || g.Resolve(Identity{TID: 10}, 60).TaskID != "" {
			t.Fatal("unidentified rekey inherited leader identity")
		}
		if ex := g.Execs[3]; ex != nil && ex.TaskID == g.Execs[1].TaskID {
			t.Fatal("non-leader exec merged into leader")
		}
	}
}

func TestCyclicForkEvidenceIsNotTraversable(t *testing.T) {
	g := build(t, fork(1, 11, 10, 10, 10), fork(2, 10, 11, 10, 10))
	for _, f := range g.Forks {
		if f.ParentTaskID != nil || f.Resolution != "ancestry_cycle" {
			t.Fatalf("cycle edge=%+v", f)
		}
	}
}

func TestWeakRekeyDoesNotEndFutureReusedTID(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), fork(2, 10, 11, 30, 10), event(3, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", TID: 10, TGID: 10, OldPID: 11, KernelTimeNS: 50}), execEvent(4, 10, 100, 110))
	if r := g.Resolve(Identity{TID: 10}, 120); r.TaskID != g.Execs[4].TaskID {
		t.Fatalf("future lifetime invalidated: %+v", r)
	}
}

func TestResolutionCandidatesExcludeContradictoryLifetimes(t *testing.T) {
	g := build(t, execEvent(1, 10, 10, 20), exitEvent(2, 10, 10, 50), execEvent(3, 10, 60, 70))
	for _, at := range []uint64{5, 50, 80} {
		r := g.Resolve(Identity{TID: 10, Birth: 10}, at)
		if r.TaskID != "" || len(r.Candidates) != 0 || r.Reason != "contradictory_task_lifetime" {
			t.Fatalf("at=%d: contradictory identity retained: %+v", at, r)
		}
	}
	for _, at := range []uint64{5, 55} {
		r := g.Resolve(Identity{TID: 10}, at)
		if len(r.Candidates) != 0 || r.Reason != "contradictory_task_lifetime" {
			t.Fatalf("bare TID outside known intervals at %d: %+v", at, r)
		}
	}
	// No timestamp cannot prove a contradiction, even with observed PID reuse.
	r := g.Resolve(Identity{TID: 10}, 0)
	if r.TaskID != "" || len(r.Candidates) != 2 || r.Reason != "ambiguous_task_identity" {
		t.Fatalf("unknown timing discarded candidates: %+v", r)
	}
}
