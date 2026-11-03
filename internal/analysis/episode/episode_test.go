package episode

import (
	"encoding/json"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func ev(seq int64, typ storage.EventType, d any) storage.Event {
	b, err := json.Marshal(d)
	if err != nil {
		panic(err)
	}
	return storage.Event{RunID: "r", Seq: seq, TS: 10000 - seq, Type: typ, DataJSON: b}
}
func ex(seq int64, tid int, birth, k uint64) storage.Event {
	return ev(seq, storage.TypeExec, model.ExecDetail{Filename: "/bin/tool", Argv: []string{"tool", "arg"}, TID: tid, TGID: tid, TaskStartKernelNS: birth, KernelTimeNS: k})
}
func fk(seq int64, p, c int, b, pb uint64) storage.Event {
	return ev(seq, storage.TypeProcess, model.ProcessDetail{Kind: "fork", ParentTID: p, ChildTID: c, ParentTaskStartKernelNS: pb, TaskStartKernelNS: b, KernelTimeNS: b + 1})
}
func file(seq int64, tid int, k uint64) storage.Event {
	return ev(seq, storage.TypeFile, model.FileDetail{TID: tid, KernelTimeNS: k, Op: "create_or_open", Syscall: "openat", Correlation: "complete", Path: "out", RawPath: "out", PathResolution: "unresolved", Flags: 64})
}
func net(seq int64, tid int, k uint64) storage.Event {
	return ev(seq, storage.TypeNet, model.NetDetail{TID: tid, KernelTimeNS: k, Op: "connect", Proto: "tcp", DstIP: "::1", DstPort: 443, ConnectState: "in_progress"})
}
func episodeFor(t *testing.T, root int64, events []storage.Event) Episode {
	t.Helper()
	g, err := processgraph.Build("r", events)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := Build(runs.Meta{RunID: "r", EndTS: 1000}, root, g)
	if err != nil {
		t.Fatal(err)
	}
	return ep
}
func realistic() []storage.Event {
	legacy := file(21, 0, 0)
	legacy.PID = 20
	return []storage.Event{ex(1, 10, 10, 20), fk(2, 10, 20, 30, 10), ex(3, 20, 30, 40), file(4, 20, 35), net(5, 10, 60), fk(6, 10, 30, 50, 10), ex(7, 30, 50, 55), net(8, 30, 60), fk(9, 20, 21, 60, 30), file(10, 21, 65), fk(11, 21, 22, 70, 60), ex(12, 22, 70, 80), net(13, 22, 90), ev(14, storage.TypeProcess, model.ProcessDetail{Kind: "exit", TID: 22, TaskStartKernelNS: 70, KernelTimeNS: 100}), ex(15, 20, 30, 110), file(16, 20, 115), fk(17, 20, 23, 35, 30), ex(18, 23, 35, 120), file(19, 23, 125), file(20, 999, 150), legacy, file(22, 20, 110), file(23, 20, 40), ex(24, 999, 200, 210), file(25, 999, 220)}
}

func TestRealisticEpisodeAndExclusiveAccounting(t *testing.T) {
	ep := episodeFor(t, 3, realistic())
	if ep.Summary.Processes != 3 || ep.Summary.Execs != 3 {
		t.Fatalf("summary=%+v", ep.Summary)
	}
	if want := (Counts{Observed: 9, Attributed: 3, Uncertain: 2, Unrelated: 2, Unattributable: 2}); ep.Summary.File != want {
		t.Fatalf("files=%+v want %+v", ep.Summary.File, want)
	}
	if want := (Counts{Observed: 3, Attributed: 1, Unrelated: 2}); ep.Summary.Network != want {
		t.Fatalf("net=%+v", ep.Summary.Network)
	}
	if ep.FileEvents[0].Attribution != "task_instance_only" || ep.FileEvents[0].ExecSeq != nil {
		t.Fatal("fork-only child assigned inherited exec")
	}
	if *ep.FileEvents[1].ExecSeq != 15 || ep.FileEvents[2].ExecSeq != nil {
		t.Fatalf("exec boundary=%+v", ep.FileEvents)
	}
	if *ep.NetworkEvents[0].ExecSeq != 12 {
		t.Fatal("wrong descendant generation")
	}
	for _, a := range ep.FileEvents {
		if !strings.Contains(string(a.Event.DataJSON), "create_or_open") || !strings.Contains(string(a.Event.DataJSON), "unresolved") {
			t.Fatal("file semantics changed")
		}
	}
	if !strings.Contains(string(ep.NetworkEvents[0].Event.DataJSON), "in_progress") {
		t.Fatal("connection semantics changed")
	}
	for _, c := range []Counts{ep.Summary.File, ep.Summary.Network} {
		if c.Observed != c.Attributed+c.Uncertain+c.Unrelated+c.Unattributable {
			t.Fatal("double counting")
		}
	}
	if ep.Summary.UnattributableReasons["unresolved_episode_relationship"] != 1 {
		t.Fatal("disconnected lineage not distinguished from unknown identity")
	}
}

func TestRootLaterGenerationExcludesExistingChildren(t *testing.T) {
	ep := episodeFor(t, 15, realistic())
	if ep.Summary.Processes != 1 || ep.Summary.Execs != 1 || len(ep.FileEvents) != 1 || ep.FileEvents[0].Event.Seq != 16 {
		t.Fatalf("episode=%+v", ep)
	}
	if ep.RootExec.Generation == nil || *ep.RootExec.Generation != 2 {
		t.Fatal("root generation renumbered")
	}
}

func TestRekeyAndReuseDoNotAbsorbLeaderOrLaterLifetime(t *testing.T) {
	events := []storage.Event{ex(1, 10, 10, 20), fk(2, 10, 11, 30, 10), file(3, 11, 40), ev(4, storage.TypeProcess, model.ProcessDetail{Kind: "exec_rekey", OldPID: 11, TID: 10, TGID: 10, TaskStartKernelNS: 30, KernelTimeNS: 51}), ev(5, storage.TypeExec, model.ExecDetail{TID: 10, TGID: 10, OldPID: 11, TaskStartKernelNS: 30, KernelTimeNS: 50}), file(6, 10, 60), fk(7, 1, 10, 100, 0), ex(8, 10, 100, 110), file(9, 10, 120)}
	ep := episodeFor(t, 5, events)
	if len(ep.ProcessMembers) != 1 || len(ep.ExecMembers) != 1 || len(ep.FileEvents) != 1 || ep.FileEvents[0].Event.Seq != 6 {
		t.Fatalf("episode=%+v", ep)
	}
	if ep.Summary.File.Unrelated != 1 || ep.Summary.File.Unattributable != 1 {
		t.Fatalf("reuse accounting=%+v", ep.Summary.File)
	}
}

func TestLegacyCandidatesAreNotMembers(t *testing.T) {
	a := ev(1, storage.TypeExec, model.ExecDetail{Filename: "/bin/sh"})
	a.PID = 10
	b := ev(2, storage.TypeExec, model.ExecDetail{Filename: "/bin/child"})
	b.PID = 20
	b.PPID = 10
	f := file(3, 0, 0)
	f.PID = 10
	n := net(4, 0, 0)
	n.PID = 20
	ep := episodeFor(t, 1, []storage.Event{a, b, f, n, net(5, 999, 0)})
	if len(ep.ProcessMembers) != 1 || len(ep.ExecMembers) != 1 || len(ep.UncertainEvents) != 2 || ep.Summary.Network.Unattributable != 1 {
		t.Fatalf("legacy=%+v", ep)
	}
}

func TestMissingTimeCanResolveDescendantTaskButNotGeneration(t *testing.T) {
	f := ev(4, storage.TypeFile, model.FileDetail{TID: 11, TaskStartKernelNS: 30, Op: "open"})
	ep := episodeFor(t, 1, []storage.Event{ex(1, 10, 10, 20), fk(2, 10, 11, 30, 10), ex(3, 11, 30, 40), f})
	if len(ep.FileEvents) != 1 || ep.FileEvents[0].Attribution != "task_instance_only" {
		t.Fatalf("file=%+v", ep.FileEvents)
	}
}

func TestMissingRootTimeMakesDescendantsUncertain(t *testing.T) {
	ep := episodeFor(t, 1, []storage.Event{ex(1, 10, 10, 0), fk(2, 10, 11, 30, 10), ex(3, 11, 30, 40), file(4, 11, 50)})
	if len(ep.ProcessMembers) != 1 || len(ep.UncertainEvents) != 1 || ep.Summary.File.Unrelated != 0 {
		t.Fatalf("episode=%+v", ep)
	}
}

func TestCoverageAndSelectionErrors(t *testing.T) {
	g, err := processgraph.Build("r", []storage.Event{ex(1, 10, 10, 20), file(2, 10, 30)})
	if err != nil {
		t.Fatal(err)
	}
	meta := runs.Meta{RunID: "r", Coverage: runs.Coverage{File: runs.KernelCoverage{Capture: "partial", KnownLoss: runs.KnownLoss{PersistenceFailures: 2}}}}
	ep, err := Build(meta, 1, g)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Coverage.Reported.Process.Capture != "unknown" || ep.Coverage.Reported.File.Capture != "partial" || ep.Coverage.Reported.File.KnownLoss.PersistenceFailures != 2 {
		t.Fatalf("coverage=%+v", ep.Coverage)
	}
	for _, seq := range []int64{0, -1, 2, 99} {
		if _, err := Build(meta, seq, g); err == nil {
			t.Fatalf("accepted seq %d", seq)
		}
	}
}

func TestDeterministicJSONWithShuffledEvents(t *testing.T) {
	events := realistic()
	want, err := json.Marshal(episodeFor(t, 3, events))
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(123)) //nolint:gosec // Reproducible input permutations, not security randomness.
	for i := 0; i < 20; i++ {
		rng.Shuffle(len(events), func(i, j int) { events[i], events[j] = events[j], events[i] })
		got, err := json.Marshal(episodeFor(t, 3, events))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(want, got) {
			t.Fatal("JSON depends on arrival order")
		}
	}
}

func TestBuildFanoutAndRootExitDoesNotEndChildren(t *testing.T) {
	events := []storage.Event{ex(1, 10, 10, 20)}
	for i := 0; i < 32; i++ {
		seq := int64(2 + i*3)
		birth := uint64(30 + i*10)
		events = append(events, fk(seq, 10, 100+i, birth, 10), ex(seq+1, 100+i, birth, birth+1), file(seq+2, 100+i, 1000))
	}
	events = append(events, ev(100, storage.TypeProcess, model.ProcessDetail{Kind: "exit", TID: 10, TaskStartKernelNS: 10, KernelTimeNS: 500}))
	ep := episodeFor(t, 1, events)
	if len(ep.ProcessMembers) != 33 || len(ep.ExecMembers) != 33 || len(ep.FileEvents) != 32 {
		t.Fatalf("build summary=%+v", ep.Summary)
	}
}

func BenchmarkDeepLineage(b *testing.B) {
	events := []storage.Event{ex(1, 10, 10, 20)}
	parent := 10
	parentBirth := uint64(10)
	for i := 0; i < 2000; i++ {
		tid := 100 + i
		birth := uint64(30 + i*10)
		seq := int64(2 + i*3)
		events = append(events, fk(seq, parent, tid, birth, parentBirth), ex(seq+1, tid, birth, birth+1), file(seq+2, tid, birth+2))
		parent, parentBirth = tid, birth
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g, err := processgraph.Build("r", events)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := Build(runs.Meta{RunID: "r"}, 1, g); err != nil {
			b.Fatal(err)
		}
	}
}
