package processgraph

import (
	"math"
	"sort"
)

func (g *Graph) indexBindings(bindings []*binding) {
	g.byTID = make(map[int][]*binding)
	g.byTGID = make(map[int]map[string]bool)
	g.byIdentity = make(map[string][]*binding)
	g.prefixEnd = make(map[int][]uint64)
	for _, b := range bindings {
		if b.identity.TID <= 0 {
			continue
		}
		g.byTID[b.identity.TID] = append(g.byTID[b.identity.TID], b)
		if b.identity.TGID > 0 {
			if g.byTGID[b.identity.TGID] == nil {
				g.byTGID[b.identity.TGID] = make(map[string]bool)
			}
			g.byTGID[b.identity.TGID][b.task.ID] = true
		}
		if key := identityKey(b.identity); key != "" {
			g.byIdentity[key] = append(g.byIdentity[key], b)
		}
	}
	for tid, bs := range g.byTID {
		sort.Slice(bs, func(i, j int) bool {
			if bs[i].start != bs[j].start {
				return bs[i].start < bs[j].start
			}
			return bs[i].task.ID < bs[j].task.ID
		})
		// A new independently identified incarnation ends ownership of a
		// numerical TID. This is not an invented exit observation.
		next := uint64(0)
		for i := len(bs) - 1; i >= 0; i-- {
			b := bs[i]
			if next != 0 && b.start < next && (b.end == 0 || next < b.end) {
				b.end = next
			}
			if b.reliable && b.start != 0 {
				next = b.start
			}
		}
		ends := make([]uint64, len(bs))
		for i, b := range bs {
			end := b.end
			if end == 0 {
				end = math.MaxUint64
			}
			if i > 0 && ends[i-1] > end {
				end = ends[i-1]
			}
			ends[i] = end
		}
		g.prefixEnd[tid] = ends
	}
}

// Resolve never treats a bare PID or a sole zero-birth node as strong identity.
// An interval match requires TID, kernel time, and an independently anchored
// task. Exact identity can resolve without time, but contradictory time cannot.
func (g *Graph) Resolve(id Identity, at uint64) Resolution {
	r := Resolution{Candidates: []string{}, Reason: "missing_task_identity"}
	if id.TID <= 0 {
		return r
	}
	key := identityKey(id)
	bs := g.byTID[id.TID]
	exact := key != ""
	if exact {
		bs = g.byIdentity[key]
	}
	if !exact && at != 0 {
		all := bs
		i := sort.Search(len(all), func(i int) bool { return all[i].start > at })
		start := i
		ends := g.prefixEnd[id.TID]
		for start > 0 && ends[start-1] >= at {
			start--
		}
		bs = all[start:i]
	}
	seen := make(map[string]bool)
	strong := make(map[string]bool)
	for _, b := range bs {
		if id.TGID != 0 && b.identity.TGID != 0 && id.TGID != b.identity.TGID {
			continue
		}
		compatible := at == 0 || ((b.start == 0 || at >= b.start) && (b.end == 0 || at < b.end))
		if !compatible && !exact {
			continue
		}
		seen[b.task.ID] = true
		if compatible && !b.task.Conflicted && (exact || (at != 0 && b.reliable)) {
			strong[b.task.ID] = true
		}
	}
	for id := range seen {
		r.Candidates = append(r.Candidates, id)
	}
	sort.Strings(r.Candidates)
	if len(r.Candidates) == 1 && strong[r.Candidates[0]] {
		r.TaskID = r.Candidates[0]
		r.Reason = ""
		r.Basis = "tid_kernel_interval"
		if exact {
			r.Basis = "task_identity"
		}
	} else if len(r.Candidates) > 1 {
		r.Reason = "ambiguous_task_identity"
	} else if len(r.Candidates) == 1 {
		r.Reason = "insufficient_identity_or_ordering"
	}
	return r
}

// PIDCandidates is deliberately weaker than Resolve: file/net PID may denote
// TGID, and cannot identify an emitting thread. It is only candidate evidence.
func (g *Graph) PIDCandidates(pid int) []string {
	seen := make(map[string]bool)
	for _, b := range g.byTID[pid] {
		seen[b.task.ID] = true
	}
	for id := range g.byTGID[pid] {
		seen[id] = true
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
