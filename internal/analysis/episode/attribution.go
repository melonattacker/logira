package episode

import (
	"strings"

	"github.com/melonattacker/logira/internal/analysis/processgraph"
)

func attribute(ep *Episode, g *processgraph.Graph, l lineage, o processgraph.Observation) {
	counts := &ep.Summary.File
	if o.Net != nil {
		counts = &ep.Summary.Network
	}
	counts.Observed++
	r := g.Resolve(o.Identity, o.KernelNS)
	a := Activity{Event: o.Event, Attribution: "uncertain", Basis: r.Basis, Reason: r.Reason}
	if r.TaskID != "" {
		a.TaskID = &r.TaskID
		if e, member := l.members[r.TaskID]; member {
			switch {
			case e.wholeLifetime || (e.at != 0 && o.KernelNS > e.at):
				a.Attribution = "task_instance_only"
				a.Reason = "missing_or_ambiguous_exec_generation"
				if ex := g.ExecAt(r.TaskID, o.KernelNS); ex != nil && l.execs[ex.Event.Seq] {
					seq := ex.Event.Seq
					a.ExecSeq = &seq
					a.Generation = ex.Generation
					a.Attribution = "task_and_exec_generation"
					a.Reason = ""
				}
				counts.Attributed++
				if o.File != nil {
					ep.FileEvents = append(ep.FileEvents, a)
					fileLimitations(ep, o)
				} else {
					ep.NetworkEvents = append(ep.NetworkEvents, a)
				}
				return
			case e.at != 0 && o.KernelNS != 0 && o.KernelNS < e.at:
				counts.Unrelated++
				return
			default:
				a.Reason = "uncertain_root_exec_boundary"
				counts.Uncertain++
				ep.UncertainEvents = append(ep.UncertainEvents, a)
				return
			}
		}
		if l.outside[r.TaskID] {
			counts.Unrelated++
			return
		}
		if l.uncertain[r.TaskID] {
			a.Reason = "uncertain_descendant_membership"
			counts.Uncertain++
			ep.UncertainEvents = append(ep.UncertainEvents, a)
			return
		}
		counts.Unattributable++
		ep.Summary.UnattributableReasons["unresolved_episode_relationship"]++
		return
	}
	// A PID-only observation is never promoted to definite attribution. It can
	// identify candidate evidence, including old runs without TID/kernel time.
	if o.Identity.TID == 0 {
		pid := o.Identity.TGID
		if pid == 0 {
			pid = o.Event.PID
		}
		if pid == 0 && o.File != nil {
			pid = o.File.PID
		}
		if pid == 0 && o.Net != nil {
			pid = o.Net.PID
		}
		r.Candidates = g.PIDCandidates(pid)
		a.Reason = "pid_only_identity"
	}
	for _, id := range r.Candidates {
		if _, ok := l.members[id]; ok || l.uncertain[id] {
			counts.Uncertain++
			ep.UncertainEvents = append(ep.UncertainEvents, a)
			return
		}
	}
	counts.Unattributable++
	ep.Summary.UnattributableReasons[a.Reason]++
}

func fileLimitations(ep *Episode, o processgraph.Observation) {
	d := o.File
	for _, value := range []string{d.PathResolution, d.PathResolution2} {
		if strings.Contains(value, "unresolved") || strings.Contains(value, "best_effort") {
			ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "uncertain_path_resolution", Seq: o.Event.Seq})
			break
		}
	}
	if d.Correlation == "incomplete" {
		ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "incomplete_file_correlation", Seq: o.Event.Seq})
	}
}
