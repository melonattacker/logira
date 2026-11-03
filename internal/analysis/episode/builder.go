package episode

import (
	"fmt"
	"sort"

	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type entry struct {
	seq           int64
	kind          string
	at            uint64
	wholeLifetime bool
}
type lineage struct {
	members   map[string]entry
	uncertain map[string]bool
	outside   map[string]bool
	execs     map[int64]bool
}

// Build uses the observations already decoded by the graph, avoiding a second
// potentially different event stream for membership and attribution.
func Build(meta runs.Meta, rootExecSeq int64, g *processgraph.Graph) (Episode, error) {
	var ep Episode
	if rootExecSeq <= 0 {
		return ep, fmt.Errorf("--exec-seq must be a positive sequence number")
	}
	if g == nil {
		return ep, fmt.Errorf("process graph is required")
	}
	if meta.RunID != "" && meta.RunID != g.RunID {
		return ep, fmt.Errorf("metadata run_id %q does not match %q", meta.RunID, g.RunID)
	}
	root := g.Execs[rootExecSeq]
	if root == nil {
		for _, o := range g.Observations {
			if o.Event.Seq == rootExecSeq {
				return ep, fmt.Errorf("sequence %d is %s, not exec; select an exec with 'logira query --type exec'", rootExecSeq, o.Event.Type)
			}
		}
		return ep, fmt.Errorf("exec sequence %d was not found in run %s", rootExecSeq, g.RunID)
	}
	ep = Episode{
		SchemaVersion: 1, RunID: g.RunID, RootExecSeq: rootExecSeq, RootExec: *root,
		ProcessMembers: []ProcessMember{}, Relationships: []processgraph.Fork{},
		ExecMembers: []processgraph.Exec{}, FileEvents: []Activity{}, NetworkEvents: []Activity{},
		UncertainEvents: []Activity{}, Limitations: []processgraph.Issue{},
		Summary:        Summary{UnattributableReasons: map[string]int{}, IgnoredTypes: map[string]int{}},
		Coverage:       Coverage{Scope: "run", Reported: meta.Coverage, Ancestry: "unknown", ActivityScope: "retained_events"},
		AnalysisSource: Source{Events: "provided_observations", Metadata: "provided_metadata", Finalized: meta.EndTS != 0},
	}
	l := selectLineage(g, root)
	for _, t := range g.Tasks {
		e, ok := l.members[t.ID]
		if !ok {
			if l.uncertain[t.ID] {
				for _, seq := range t.ExecSeqs {
					ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "uncertain_exec_membership", Seq: seq, TaskID: t.ID})
				}
			}
			continue
		}
		ep.ProcessMembers = append(ep.ProcessMembers, ProcessMember{Task: *t, EntrySeq: e.seq, EntryKind: e.kind})
		for _, seq := range t.ExecSeqs {
			ex := g.Execs[seq]
			if seq == rootExecSeq || (e.wholeLifetime && !t.Conflicted) || (e.at != 0 && ex.Detail.KernelTimeNS > e.at && !t.Conflicted) {
				ep.ExecMembers = append(ep.ExecMembers, *ex)
			} else if ex.Detail.KernelTimeNS == 0 || e.at == 0 || ex.Detail.KernelTimeNS == e.at || t.Conflicted {
				ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "uncertain_exec_membership", Seq: seq, TaskID: t.ID})
			}
		}
	}
	for _, f := range g.Forks {
		if _, ok := l.members[f.ChildTaskID]; ok {
			ep.Relationships = append(ep.Relationships, *f)
		} else if l.uncertain[f.ChildTaskID] {
			ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "uncertain_descendant_membership", Seq: f.Seq, TaskID: f.ChildTaskID})
		}
	}
	for _, issue := range g.Issues {
		if _, ok := l.members[issue.TaskID]; ok {
			ep.Limitations = append(ep.Limitations, issue)
			ep.Coverage.Ancestry = "partial"
		}
	}
	for _, ex := range ep.ExecMembers {
		l.execs[ex.Event.Seq] = true
	}
	for _, o := range g.Observations {
		if o.Event.Seq > ep.AnalysisSource.MaxSeq {
			ep.AnalysisSource.MaxSeq = o.Event.Seq
		}
		if o.File == nil && o.Net == nil {
			if o.Event.Type != storage.TypeExec && o.Event.Type != storage.TypeProcess && o.Event.Type != storage.TypeDetection {
				ep.Summary.IgnoredTypes[string(o.Event.Type)]++
			}
			continue
		}
		attribute(&ep, g, l, o)
	}
	for _, pair := range []struct {
		name string
		c    *runs.KernelCoverage
	}{{"process", &ep.Coverage.Reported.Process}, {"file", &ep.Coverage.Reported.File}, {"network", &ep.Coverage.Reported.Network}} {
		if pair.c.Availability == "" {
			pair.c.Availability = "unknown"
		}
		if pair.c.Capture == "" {
			pair.c.Capture = "unknown"
		}
		code := pair.name + "_capture_" + pair.c.Capture
		if pair.c.Capture == "complete" {
			code = pair.name + "_reported_complete_unverified"
		}
		ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: code})
	}
	if !ep.AnalysisSource.Finalized {
		ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "run_not_finalized"})
	}
	ep.Summary.Processes = len(ep.ProcessMembers)
	ep.Summary.Execs = len(ep.ExecMembers)
	sort.Slice(ep.ExecMembers, func(i, j int) bool { return ep.ExecMembers[i].Event.Seq < ep.ExecMembers[j].Event.Seq })
	SortLimitations(ep.Limitations)
	return ep, nil
}

func selectLineage(g *processgraph.Graph, root *processgraph.Exec) lineage {
	l := lineage{members: map[string]entry{root.TaskID: {seq: root.Event.Seq, kind: "exec", at: root.Detail.KernelTimeNS}}, uncertain: map[string]bool{}, outside: map[string]bool{}, execs: map[int64]bool{}}
	queue := []string{root.TaskID}
	for i := 0; i < len(queue); i++ {
		id := queue[i]
		e, member := l.members[id]
		for _, f := range g.Children[id] {
			child := f.ChildTaskID
			if _, visited := l.members[child]; visited || l.uncertain[child] || l.outside[child] {
				continue
			}
			switch {
			case l.outside[id]:
				l.outside[child] = true
			case !member || g.Task(id).Conflicted:
				l.uncertain[child] = true
			case e.wholeLifetime || (e.at != 0 && f.KernelNS > e.at):
				l.members[child] = entry{seq: f.Seq, kind: "fork", at: f.KernelNS, wholeLifetime: true}
			case e.at != 0 && f.KernelNS != 0 && f.KernelNS < e.at:
				l.outside[child] = true
			default:
				l.uncertain[child] = true
			}
			queue = append(queue, child)
		}
	}
	// An observed ancestor/sibling is unrelated, whereas a disconnected node
	// with missing ancestry cannot be declared unrelated just by exclusion.
	neighbors := make(map[string][]string)
	for _, f := range g.Forks {
		if f.ParentTaskID != nil {
			p := *f.ParentTaskID
			neighbors[p] = append(neighbors[p], f.ChildTaskID)
			neighbors[f.ChildTaskID] = append(neighbors[f.ChildTaskID], p)
		}
	}
	queue = []string{root.TaskID}
	seen := map[string]bool{root.TaskID: true}
	for i := 0; i < len(queue); i++ {
		for _, id := range neighbors[queue[i]] {
			if seen[id] {
				continue
			}
			seen[id] = true
			queue = append(queue, id)
			if _, ok := l.members[id]; !ok && !l.uncertain[id] {
				l.outside[id] = true
			}
		}
	}
	// PPID is candidate evidence only. It never creates an edge or member.
	memberTIDs := make(map[int]bool)
	for id := range l.members {
		for _, identity := range g.Task(id).Identities {
			if identity.TID > 0 {
				memberTIDs[identity.TID] = true
			}
		}
	}
	for _, o := range g.Observations {
		if o.Exec != nil && o.Event.PPID > 0 && memberTIDs[o.Event.PPID] {
			id := g.Execs[o.Event.Seq].TaskID
			if _, ok := l.members[id]; !ok && !l.outside[id] {
				l.uncertain[id] = true
			}
		}
	}
	// Unresolved observed forks may still connect a candidate to a member.
	// Propagate only uncertainty, never promote these edges into membership.
	candidateChildren := make(map[string][]string)
	for _, f := range g.Forks {
		if f.ParentTaskID != nil {
			candidateChildren[*f.ParentTaskID] = append(candidateChildren[*f.ParentTaskID], f.ChildTaskID)
			continue
		}
		for _, id := range g.Resolve(f.ParentIdentity, f.KernelNS).Candidates {
			candidateChildren[id] = append(candidateChildren[id], f.ChildTaskID)
		}
	}
	queue = queue[:0]
	seen = make(map[string]bool)
	for id := range l.members {
		queue = append(queue, id)
		seen[id] = true
	}
	for id := range l.uncertain {
		queue = append(queue, id)
		seen[id] = true
	}
	for i := 0; i < len(queue); i++ {
		for _, child := range candidateChildren[queue[i]] {
			if seen[child] || l.outside[child] {
				continue
			}
			seen[child] = true
			l.uncertain[child] = true
			queue = append(queue, child)
		}
	}
	return l
}

func SortLimitations(issues []processgraph.Issue) {
	sort.Slice(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.TaskID != b.TaskID {
			return a.TaskID < b.TaskID
		}
		return a.Seq < b.Seq
	})
}
