package processgraph

import (
	"fmt"
	"sort"

	"github.com/melonattacker/logira/internal/storage"
)

type transition struct {
	old, new            string
	at                  uint64
	execSeqs, rekeySeqs []int64
}

// Build decodes once and constructs identities before linking ancestry. Sorting
// the input by sequence only stabilizes IDs/output; it does not establish cause.
func Build(runID string, events []storage.Event) (*Graph, error) {
	g := &Graph{RunID: runID, Tasks: []*Task{}, Execs: make(map[int64]*Exec), Forks: []*Fork{}, Children: make(map[string][]*Fork), Issues: []Issue{}, tasks: make(map[string]*Task), barriers: make(map[string][]uint64), unknownBarrier: make(map[string]bool)}
	ordered := append([]storage.Event(nil), events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Seq < ordered[j].Seq })
	for i, ev := range ordered {
		if ev.RunID != runID {
			return nil, fmt.Errorf("seq %d: run_id %q does not match %q", ev.Seq, ev.RunID, runID)
		}
		if ev.Seq <= 0 || (i > 0 && ordered[i-1].Seq == ev.Seq) {
			return nil, fmt.Errorf("invalid or duplicate event sequence %d", ev.Seq)
		}
		o, err := decode(ev)
		if err != nil {
			return nil, err
		}
		g.Observations = append(g.Observations, o)
	}
	parents := make(map[string]string)
	identities := make(map[string]Identity)
	anchors := make(map[string]int64)
	add := func(key string, id Identity, seq int64) {
		if _, ok := parents[key]; !ok {
			parents[key] = key
			identities[key] = id
			anchors[key] = seq
		}
		if seq < anchors[key] {
			anchors[key] = seq
		}
		if identities[key].TGID == 0 && id.TGID != 0 {
			old := identities[key]
			old.TGID = id.TGID
			identities[key] = old
		}
	}
	var find func(string) string
	find = func(k string) string {
		if parents[k] != k {
			parents[k] = find(parents[k])
		}
		return parents[k]
	}
	transitions := make(map[string]*transition)
	for _, o := range g.Observations {
		if o.Exec == nil && o.Process == nil {
			continue
		}
		key := identityKey(o.Identity)
		if key == "" {
			continue
		}
		add(key, o.Identity, o.Event.Seq)
		oldPID := 0
		if o.Exec != nil {
			oldPID = o.Exec.OldPID
		} else if o.Process.Kind == "exec_rekey" {
			oldPID = o.Process.OldPID
		}
		if oldPID <= 0 || oldPID == o.Identity.TID {
			continue
		}
		oldID := o.Identity
		oldID.TID = oldPID
		oldKey := identityKey(oldID)
		add(oldKey, oldID, o.Event.Seq)
		a, b := find(oldKey), find(key)
		if a != b {
			if a > b {
				a, b = b, a
			}
			parents[b] = a
		}
		tk := oldKey + "->" + key
		tr := transitions[tk]
		if tr == nil {
			tr = &transition{old: oldKey, new: key}
			transitions[tk] = tr
		}
		if o.KernelNS != 0 && (tr.at == 0 || o.KernelNS < tr.at) {
			tr.at = o.KernelNS
		}
		if o.Exec != nil {
			tr.execSeqs = append(tr.execSeqs, o.Event.Seq)
		} else {
			tr.rekeySeqs = append(tr.rekeySeqs, o.Event.Seq)
		}
	}
	keys := make([]string, 0, len(parents))
	for k := range parents {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	groups := make(map[string]*Task)
	for _, k := range keys {
		root := find(k)
		t := groups[root]
		if t == nil {
			t = newTask(anchors[k])
			groups[root] = t
		}
		if anchors[k] < t.anchor {
			t.anchor = anchors[k]
		}
	}
	for _, t := range groups {
		t.ID = fmt.Sprintf("task:%d", t.anchor)
		g.Tasks = append(g.Tasks, t)
		g.tasks[t.ID] = t
	}
	bindings := make([]*binding, 0, len(keys))
	byKey := make(map[string]*binding)
	for _, k := range keys {
		id := identities[k]
		start := id.Birth
		if start == 0 {
			start = id.FirstObserved
		}
		b := &binding{task: groups[find(k)], identity: id, start: start, reliable: true}
		bindings = append(bindings, b)
		byKey[k] = b
		b.task.Identities = append(b.task.Identities, id)
	}
	trKeys := make([]string, 0, len(transitions))
	for k := range transitions {
		trKeys = append(trKeys, k)
	}
	sort.Strings(trKeys)
	for _, k := range trKeys {
		tr := transitions[k]
		old, newB := byKey[tr.old], byKey[tr.new]
		if tr.at != 0 {
			old.end = tr.at
			newB.start = tr.at
		} else {
			old.reliable = false
			newB.reliable = false
		}
		if len(tr.execSeqs) != 1 {
			if tr.at == 0 {
				g.unknownBarrier[newB.task.ID] = true
			} else {
				g.barriers[newB.task.ID] = append(g.barriers[newB.task.ID], tr.at)
			}
			g.Issues = append(g.Issues, Issue{Code: "unpaired_rekey", TaskID: newB.task.ID})
		}
	}
	assigned := make(map[int64]*binding)
	// Seed all strong identities and observed weak forks before resolving weaker
	// records. An absent task_start field does not erase an actual fork record.
	for _, o := range g.Observations {
		if o.Exec == nil && o.Process == nil {
			continue
		}
		b := byKey[identityKey(o.Identity)]
		if b == nil && o.Process != nil && o.Process.Kind == "fork" {
			b = g.newBinding(o, true)
			bindings = append(bindings, b)
		}
		if b != nil {
			assigned[o.Event.Seq] = b
			g.record(o, b)
		}
	}
	g.indexBindings(bindings)
	for _, o := range g.Observations {
		if (o.Exec == nil && o.Process == nil) || assigned[o.Event.Seq] != nil {
			continue
		}
		r := g.Resolve(o.Identity, o.KernelNS)
		oldPID := 0
		if o.Exec != nil {
			oldPID = o.Exec.OldPID
		} else if o.Process.Kind == "exec_rekey" {
			oldPID = o.Process.OldPID
		}
		weakTransition := oldPID > 0 && oldPID != o.Identity.TID
		if weakTransition {
			// Without a birth/observation marker, resolving the NEW numerical
			// TID could select the displaced leader. Keep the transition opaque
			// and end numerical ownership, without manufacturing an exit.
			r.TaskID = ""
			for _, tid := range []int{oldPID, o.Identity.TID} {
				for _, prior := range g.byTID[tid] {
					if o.KernelNS == 0 {
						prior.task.Conflicted = true
						g.Issues = append(g.Issues, Issue{Code: "unknown_rekey_boundary", Seq: o.Event.Seq, TaskID: prior.task.ID})
					}
					if o.KernelNS != 0 && (prior.start == 0 || prior.start <= o.KernelNS) && (prior.end == 0 || o.KernelNS < prior.end) {
						prior.end = o.KernelNS
					}
				}
			}
		}
		var b *binding
		if r.TaskID != "" {
			for _, candidate := range g.byTID[o.Identity.TID] {
				if candidate.task.ID == r.TaskID {
					b = candidate
					break
				}
			}
		}
		if b == nil {
			b = g.newBinding(o, false)
			bindings = append(bindings, b)
		}
		assigned[o.Event.Seq] = b
		g.record(o, b)
		if weakTransition && o.Exec != nil {
			g.Issues = append(g.Issues, Issue{Code: "unresolved_rekey", Seq: o.Event.Seq, TaskID: b.task.ID})
		}
	}
	g.indexBindings(bindings)
	for _, o := range g.Observations {
		if b := assigned[o.Event.Seq]; b != nil {
			g.checkLifetime(o, b)
		}
	}
	for _, o := range g.Observations {
		if o.Process == nil || o.Process.Kind != "fork" {
			continue
		}
		d := o.Process
		child := assigned[o.Event.Seq].task
		id := Identity{TID: d.ParentTID, TGID: d.ParentTGID, Birth: d.ParentTaskStartKernelNS}
		f := &Fork{Seq: o.Event.Seq, KernelNS: o.KernelNS, ParentIdentity: id, ChildTaskID: child.ID, CloneKind: normalize(d.CloneKind, "thread_clone", "process_fork"), Resolution: "unresolved_parent"}
		r := g.Resolve(id, o.KernelNS)
		if r.TaskID != "" && r.TaskID != child.ID && len(child.ForkSeqs) == 1 && !child.Conflicted {
			f.ParentTaskID = &r.TaskID
			f.Resolution = "observed_fork"
		} else {
			g.Issues = append(g.Issues, Issue{Code: "unresolved_parent", Seq: f.Seq, TaskID: child.ID})
		}
		g.Forks = append(g.Forks, f)
	}
	g.removeCycles()
	for _, f := range g.Forks {
		if f.ParentTaskID != nil {
			g.Children[*f.ParentTaskID] = append(g.Children[*f.ParentTaskID], f)
		}
	}
	for _, t := range g.Tasks {
		sort.Slice(t.Identities, func(i, j int) bool { return t.Identities[i].TID < t.Identities[j].TID })
		if len(t.ForkSeqs) == 0 {
			g.Issues = append(g.Issues, Issue{Code: "missing_fork", TaskID: t.ID})
		}
		birthKnown := false
		for _, id := range t.Identities {
			birthKnown = birthKnown || id.Birth != 0
		}
		if !birthKnown {
			g.Issues = append(g.Issues, Issue{Code: "unknown_task_birth", TaskID: t.ID})
		}
		if len(t.ExitSeqs) == 0 {
			g.Issues = append(g.Issues, Issue{Code: "missing_exit", TaskID: t.ID})
		}
		g.orderExecs(t)
	}
	sort.Slice(g.Tasks, func(i, j int) bool { return g.Tasks[i].anchor < g.Tasks[j].anchor })
	sort.Slice(g.Issues, func(i, j int) bool {
		a, b := g.Issues[i], g.Issues[j]
		if a.TaskID != b.TaskID {
			return a.TaskID < b.TaskID
		}
		if a.Seq != b.Seq {
			return a.Seq < b.Seq
		}
		return a.Code < b.Code
	})
	return g, nil
}

func newTask(seq int64) *Task {
	return &Task{ID: fmt.Sprintf("task:%d", seq), anchor: seq, Identities: []Identity{}, ForkSeqs: []int64{}, ExitSeqs: []int64{}, ExecSeqs: []int64{}, RekeySeqs: []int64{}, GroupDead: "unknown"}
}

func (g *Graph) newBinding(o Observation, reliable bool) *binding {
	t := newTask(o.Event.Seq)
	t.Identities = append(t.Identities, o.Identity)
	g.Tasks = append(g.Tasks, t)
	g.tasks[t.ID] = t
	return &binding{task: t, identity: o.Identity, start: o.KernelNS, reliable: reliable && o.KernelNS != 0}
}

func (g *Graph) record(o Observation, b *binding) {
	t := b.task
	if o.Exec != nil {
		t.ExecSeqs = append(t.ExecSeqs, o.Event.Seq)
		g.Execs[o.Event.Seq] = &Exec{Event: o.Event, TaskID: t.ID, Detail: *o.Exec}
		return
	}
	d := o.Process
	switch d.Kind {
	case "fork":
		t.ForkSeqs = append(t.ForkSeqs, o.Event.Seq)
	case "exit":
		t.ExitSeqs = append(t.ExitSeqs, o.Event.Seq)
		t.GroupDead = normalize(d.GroupDead, "true", "false")
		if o.KernelNS != 0 && (b.end == 0 || o.KernelNS < b.end) {
			b.end = o.KernelNS
		}
	case "exec_rekey":
		t.RekeySeqs = append(t.RekeySeqs, o.Event.Seq)
		if identityKey(o.Identity) == "" {
			if o.KernelNS == 0 {
				g.unknownBarrier[t.ID] = true
			} else {
				g.barriers[t.ID] = append(g.barriers[t.ID], o.KernelNS)
			}
			g.Issues = append(g.Issues, Issue{Code: "unresolved_rekey", Seq: o.Event.Seq, TaskID: t.ID})
		}
	}
}

func (g *Graph) checkLifetime(o Observation, b *binding) {
	if o.KernelNS != 0 && ((b.start != 0 && o.KernelNS < b.start) || (b.end != 0 && o.KernelNS > b.end)) {
		b.task.Conflicted = true
		g.Issues = append(g.Issues, Issue{Code: "conflicting_lifetime", Seq: o.Event.Seq, TaskID: b.task.ID})
	}
	if o.Identity.TGID != 0 && b.identity.TGID != 0 && o.Identity.TGID != b.identity.TGID {
		b.task.Conflicted = true
		g.Issues = append(g.Issues, Issue{Code: "conflicting_thread_group", Seq: o.Event.Seq, TaskID: b.task.ID})
	}
}

func (g *Graph) orderExecs(t *Task) {
	sort.Slice(t.ExecSeqs, func(i, j int) bool {
		a, b := g.Execs[t.ExecSeqs[i]], g.Execs[t.ExecSeqs[j]]
		if a.Detail.KernelTimeNS != b.Detail.KernelTimeNS {
			return a.Detail.KernelTimeNS < b.Detail.KernelTimeNS
		}
		return a.Event.Seq < b.Event.Seq
	})
	ambiguous := t.Conflicted
	for i, seq := range t.ExecSeqs {
		if len(t.ExecSeqs) > 1 && (g.Execs[seq].Detail.KernelTimeNS == 0 || (i > 0 && g.Execs[t.ExecSeqs[i-1]].Detail.KernelTimeNS == g.Execs[seq].Detail.KernelTimeNS)) {
			ambiguous = true
		}
	}
	if ambiguous {
		g.Issues = append(g.Issues, Issue{Code: "ambiguous_exec_order", TaskID: t.ID})
		return
	}
	for i, seq := range t.ExecSeqs {
		n := i + 1
		g.Execs[seq].Generation = &n
		if i > 0 {
			prev := t.ExecSeqs[i-1]
			g.Execs[seq].PreviousExecSeq = &prev
		}
	}
}

// Each resolved child has one fork parent. Walk each component once and remove
// every edge in a cycle rather than choosing an arbitrary traversal winner.
func (g *Graph) removeCycles() {
	parent := make(map[string]*Fork)
	for _, f := range g.Forks {
		if f.ParentTaskID != nil {
			parent[f.ChildTaskID] = f
		}
	}
	done := make(map[string]bool)
	for _, t := range g.Tasks {
		path := []string{}
		positions := make(map[string]int)
		id := t.ID
		for !done[id] {
			if at, ok := positions[id]; ok {
				for _, cycleID := range path[at:] {
					f := parent[cycleID]
					f.ParentTaskID = nil
					f.Resolution = "ancestry_cycle"
					g.Issues = append(g.Issues, Issue{Code: "ancestry_cycle", Seq: f.Seq, TaskID: cycleID})
				}
				break
			}
			positions[id] = len(path)
			path = append(path, id)
			f := parent[id]
			if f == nil {
				break
			}
			id = *f.ParentTaskID
		}
		for _, id := range path {
			done[id] = true
		}
	}
}

func normalize(value, a, b string) string {
	if value == a || value == b {
		return value
	}
	return "unknown"
}
