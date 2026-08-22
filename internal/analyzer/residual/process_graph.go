package residual

import (
	"encoding/json"
	"sort"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

type taskIdentity struct {
	tid   int
	start uint64
}

type forkObservation struct {
	ev         storage.Event
	kernelNS   uint64
	parent     taskIdentity
	parentTGID int
	child      taskIdentity
	childTGID  int
	cloneKind  string
}

type lifecycleNode struct {
	identity   taskIdentity
	tgid       int
	parent     taskIdentity
	parentTGID int
	forkSeq    int64
	forkTS     int64
	exitSeq    int64
	exitTS     int64
	cloneKind  string
	groupDead  string
}

type processGraph struct {
	forks  []forkObservation
	nodes  map[taskIdentity]*lifecycleNode
	rekeys map[taskIdentity]taskIdentity
}

func collectProcessGraph(events []storage.Event) *processGraph {
	g := &processGraph{
		nodes:  make(map[taskIdentity]*lifecycleNode),
		rekeys: make(map[taskIdentity]taskIdentity),
	}
	for _, ev := range events {
		if ev.Type != storage.TypeProcess {
			continue
		}
		var d model.ProcessDetail
		if json.Unmarshal(ev.DataJSON, &d) != nil {
			continue
		}
		switch d.Kind {
		case "fork":
			child := taskIdentity{tid: d.ChildTID, start: d.TaskStartKernelNS}
			if child.tid <= 0 {
				continue
			}
			parent := taskIdentity{tid: d.ParentTID, start: d.ParentTaskStartKernelNS}
			fork := forkObservation{
				ev: ev, kernelNS: d.KernelTimeNS, parent: parent, parentTGID: d.ParentTGID,
				child: child, childTGID: d.ChildTGID, cloneKind: d.CloneKind,
			}
			g.forks = append(g.forks, fork)
			g.nodes[child] = &lifecycleNode{
				identity: child, tgid: d.ChildTGID, parent: parent, parentTGID: d.ParentTGID,
				forkSeq: ev.Seq, forkTS: ev.TS, cloneKind: normalizedCloneKind(d.CloneKind),
			}
		case "exec_rekey":
			if d.OldPID <= 0 || d.TID <= 0 || d.OldPID == d.TID {
				continue
			}
			oldIdentity := taskIdentity{tid: d.OldPID, start: d.TaskStartKernelNS}
			newIdentity := taskIdentity{tid: d.TID, start: d.TaskStartKernelNS}
			g.rekeys[oldIdentity] = newIdentity
			if oldNode := g.nodes[oldIdentity]; oldNode != nil {
				copyNode := *oldNode
				copyNode.identity = newIdentity
				copyNode.tgid = d.TGID
				g.nodes[newIdentity] = &copyNode
			}
		case "exit":
			identity := taskIdentity{tid: d.TID, start: d.TaskStartKernelNS}
			if identity.tid <= 0 {
				continue
			}
			node := g.nodes[identity]
			if node == nil {
				node = &lifecycleNode{identity: identity, tgid: d.TGID}
				g.nodes[identity] = node
			}
			node.exitSeq = ev.Seq
			node.exitTS = ev.TS
			node.groupDead = normalizedGroupDead(d.GroupDead)
		}
	}
	sort.Slice(g.forks, func(i, j int) bool {
		if g.forks[i].kernelNS == g.forks[j].kernelNS {
			return g.forks[i].ev.Seq < g.forks[j].ev.Seq
		}
		return g.forks[i].kernelNS < g.forks[j].kernelNS
	})
	return g
}

func normalizedCloneKind(kind string) string {
	switch kind {
	case "thread_clone", "process_fork":
		return kind
	default:
		return "unknown"
	}
}

func normalizedGroupDead(value string) string {
	switch value {
	case "true", "false":
		return value
	default:
		return "unknown"
	}
}

func (g *processGraph) identityForExec(d model.ExecDetail, ev storage.Event) taskIdentity {
	tid := d.TID
	if tid <= 0 {
		tid = ev.PID
	}
	identity := taskIdentity{tid: tid, start: d.TaskStartKernelNS}
	if identity.start == 0 {
		if fork := g.forkForChild(identity, d.KernelTimeNS); fork != nil {
			identity.start = fork.child.start
		}
	}
	return identity
}

func (g *processGraph) forkForChild(child taskIdentity, atKernelNS uint64) *forkObservation {
	var best *forkObservation
	for i := range g.forks {
		fork := &g.forks[i]
		if fork.child.tid != child.tid {
			continue
		}
		if child.start != 0 && fork.child.start != child.start {
			continue
		}
		if atKernelNS != 0 && fork.kernelNS > atKernelNS {
			continue
		}
		if best == nil || fork.kernelNS > best.kernelNS {
			best = fork
		}
	}
	return best
}

func (g *processGraph) nearestExecParent(child taskIdentity, atKernelNS uint64, lastByTask map[taskIdentity]int, lastByTID map[int]int) int {
	seen := make(map[taskIdentity]bool)
	current := child
	for current.tid > 0 && !seen[current] {
		seen[current] = true
		fork := g.forkForChild(current, atKernelNS)
		if fork == nil || fork.parent.tid <= 0 {
			return -1
		}
		parent := fork.parent
		if idx, ok := lastByTask[parent]; ok {
			return idx
		}
		if parent.start == 0 {
			if idx, ok := lastByTID[parent.tid]; ok {
				return idx
			}
		}
		current = parent
		atKernelNS = fork.kernelNS
	}
	return -1
}

func (g *processGraph) observeExec(identity taskIdentity, d model.ExecDetail) {
	node := g.nodes[identity]
	if node == nil {
		node = &lifecycleNode{identity: identity}
		g.nodes[identity] = node
	}
	if d.TGID > 0 {
		node.tgid = d.TGID
	}
	if node.cloneKind == "unknown" && node.parentTGID > 0 && node.tgid > 0 {
		if node.tgid == node.parentTGID {
			node.cloneKind = "thread_clone"
		} else {
			node.cloneKind = "process_fork"
		}
	}
}

func (g *processGraph) episodeProcessMembers(execs []execEvent, execMembers map[int]bool, action commandAction) ([]ProcessMember, map[taskIdentity]bool) {
	const skew = int64(5_000_000_000)
	start, end := action.start-skew, action.end+skew
	included := make(map[taskIdentity]bool)
	for i := range execMembers {
		included[execs[i].identity] = true
	}

	// Effect ownership expands only from correlated exec members toward their
	// observed descendants. Walking upward would make the long-lived Codex
	// launcher an episode member and absorb its unrelated API/file activity.
	// Fork-only intermediates remain included because the downward traversal
	// reaches them before any later descendant exec.
	changed := true
	for changed {
		changed = false
		for identity, node := range g.nodes {
			if included[identity] || node.forkTS < start || node.forkTS > end {
				continue
			}
			if included[node.parent] {
				included[identity] = true
				changed = true
			}
		}
	}

	members := make([]ProcessMember, 0, len(included))
	for identity := range included {
		node := g.nodes[identity]
		member := ProcessMember{TID: identity.tid, TaskStartKernelNS: identity.start, CloneKind: "unknown", GroupDead: "unknown"}
		if node != nil {
			member.TGID = node.tgid
			member.ParentTID = node.parent.tid
			member.ParentTaskStartKernelNS = node.parent.start
			member.ParentTGID = node.parentTGID
			member.ForkSeq = node.forkSeq
			member.ExitSeq = node.exitSeq
			member.CloneKind = normalizedCloneKind(node.cloneKind)
			member.GroupDead = normalizedGroupDead(node.groupDead)
		}
		members = append(members, member)
	}
	sort.Slice(members, func(i, j int) bool {
		if members[i].TaskStartKernelNS == members[j].TaskStartKernelNS {
			return members[i].TID < members[j].TID
		}
		return members[i].TaskStartKernelNS < members[j].TaskStartKernelNS
	})
	return members, included
}
