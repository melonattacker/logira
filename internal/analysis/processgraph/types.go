// Package processgraph reconstructs observed task lifetimes without consulting
// the live machine. Identities and ordering describe evidence, not completeness.
package processgraph

import (
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
	"sort"
)

// Identity's zero fields mean unknown. Birth is the fork tracepoint observation,
// not task_struct.start_time. FirstObserved is never substituted for birth.
type Identity struct {
	TID           int    `json:"tid,omitempty"`
	TGID          int    `json:"tgid,omitempty"`
	Birth         uint64 `json:"task_start_kernel_ns,omitempty"`
	FirstObserved uint64 `json:"first_observed_kernel_ns,omitempty"`
}

type Task struct {
	ID         string     `json:"task_id"`
	Identities []Identity `json:"identities"`
	ForkSeqs   []int64    `json:"fork_seqs"`
	ExitSeqs   []int64    `json:"exit_seqs"`
	ExecSeqs   []int64    `json:"exec_seqs"`
	RekeySeqs  []int64    `json:"rekey_seqs"`
	GroupDead  string     `json:"group_dead"`
	Conflicted bool       `json:"identity_conflict"`
	anchor     int64
}

type Exec struct {
	Event           storage.Event    `json:"event"`
	TaskID          string           `json:"task_id"`
	Generation      *int             `json:"generation"`
	PreviousExecSeq *int64           `json:"previous_exec_seq"`
	Detail          model.ExecDetail `json:"-"`
}

type Fork struct {
	Seq            int64    `json:"seq"`
	KernelNS       uint64   `json:"kernel_time_ns,omitempty"`
	ParentIdentity Identity `json:"parent_identity"`
	ParentTaskID   *string  `json:"parent_task_id"`
	ChildTaskID    string   `json:"child_task_id"`
	CloneKind      string   `json:"clone_kind"`
	Resolution     string   `json:"resolution"`
}

type Issue struct {
	Code   string `json:"code"`
	Seq    int64  `json:"seq,omitempty"`
	TaskID string `json:"task_id,omitempty"`
}

// Observation retains the original payload as evidence, including unknown
// additive fields. Typed details are only used for reconstruction.
type Observation struct {
	Event    storage.Event
	Identity Identity
	KernelNS uint64
	Exec     *model.ExecDetail
	Process  *model.ProcessDetail
	File     *model.FileDetail
	Net      *model.NetDetail
}

// Resolution.Candidates contains only identities not contradicted by the supplied
// time and identity fields. Unknown timing can leave candidates unresolved; an
// exact identity outside its observed lifetime is not a candidate.
type Resolution struct {
	TaskID     string
	Candidates []string
	Basis      string
	Reason     string
}

type Graph struct {
	RunID          string
	Tasks          []*Task
	Execs          map[int64]*Exec
	Forks          []*Fork
	Children       map[string][]*Fork
	Observations   []Observation
	Issues         []Issue
	byTID          map[int][]*binding
	byTGID         map[int]map[string]bool
	byIdentity     map[string][]*binding
	prefixEnd      map[int][]uint64
	tasks          map[string]*Task
	barriers       map[string][]uint64
	unknownBarrier map[string]bool
}

type binding struct {
	task       *Task
	identity   Identity
	start, end uint64
	reliable   bool
}

func (g *Graph) Task(id string) *Task { return g.tasks[id] }

// ExecAt returns a unique observed generation. Missing timestamps, equal-time
// boundaries, and unmatched rekeys prevent a definite generation assignment.
func (g *Graph) ExecAt(taskID string, at uint64) *Exec {
	t := g.tasks[taskID]
	if t == nil || at == 0 || g.unknownBarrier[taskID] {
		return nil
	}
	if len(t.ExecSeqs) == 0 || g.Execs[t.ExecSeqs[0]].Detail.KernelTimeNS == 0 {
		return nil
	}
	i := sort.Search(len(t.ExecSeqs), func(i int) bool { return g.Execs[t.ExecSeqs[i]].Detail.KernelTimeNS >= at })
	if i == 0 || (i < len(t.ExecSeqs) && g.Execs[t.ExecSeqs[i]].Detail.KernelTimeNS == at) {
		return nil
	}
	latest := g.Execs[t.ExecSeqs[i-1]]
	if latest.Generation == nil {
		return nil
	}
	for _, boundary := range g.barriers[taskID] {
		if boundary >= latest.Detail.KernelTimeNS && boundary <= at {
			return nil
		}
	}
	return latest
}
