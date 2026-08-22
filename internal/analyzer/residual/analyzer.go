package residual

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type Classification string

const (
	Matched             Classification = "MATCHED"
	ReportedNotObserved Classification = "REPORTED_NOT_OBSERVED"
	ObservedNotReported Classification = "OBSERVED_NOT_REPORTED"
	Blocked             Classification = "BLOCKED"
	Unobservable        Classification = "UNOBSERVABLE"
)

type Finding struct {
	Classification Classification `json:"classification"`
	Confidence     string         `json:"confidence,omitempty"`
	Reason         string         `json:"reason,omitempty"`
	ItemID         string         `json:"item_id,omitempty"`
	Command        string         `json:"command,omitempty"`
	AgentSeq       int64          `json:"agent_seq,omitempty"`
	ExecSeq        int64          `json:"exec_seq,omitempty"`
	PID            int            `json:"pid,omitempty"`
	ExecSummary    string         `json:"exec_summary,omitempty"`
}

type Report struct {
	RunID    string                 `json:"run_id"`
	Findings []Finding              `json:"findings"`
	Counts   map[Classification]int `json:"counts"`
}

type commandAction struct {
	itemID, command, status string
	start, end, seq         int64
}

type execEvent struct {
	ev         storage.Event
	detail     model.ExecDetail
	generation int
	parent     int
}

func Analyze(meta runs.Meta, events []storage.Event) Report {
	report := Report{RunID: meta.RunID, Counts: make(map[Classification]int)}
	commands := collectCommands(events)
	execs := collectExecs(events)
	launchers := launcherExecs(meta, events, execs, commands)
	used := make(map[int]bool)

	for _, command := range commands {
		idx, confidence, ambiguous := bestCandidate(meta, command, execs, used, launchers)
		if idx >= 0 && !ambiguous {
			episodeSize := attributeEpisode(command, idx, execs, used)
			root := execs[idx]
			reason := fmt.Sprintf("runtime command correlated with kernel exec; execution episode contains %d exec observation(s)", episodeSize)
			if strings.EqualFold(command.status, "declined") {
				reason += "; runtime status declined conflicts with observed execution"
			}
			report.add(Finding{Classification: Matched, Confidence: confidence, Reason: reason, ItemID: command.itemID, Command: command.command, AgentSeq: command.seq, ExecSeq: root.ev.Seq, PID: root.ev.PID, ExecSummary: root.ev.Summary})
			continue
		}
		if strings.EqualFold(command.status, "declined") {
			report.add(Finding{Classification: Blocked, Confidence: "high", Reason: "Codex runtime reported status declined", ItemID: command.itemID, Command: command.command, AgentSeq: command.seq})
			continue
		}
		reason := "no matching process execution observed"
		confidence = "medium"
		if ambiguous {
			reason = "multiple equally plausible process executions; no match forced"
			confidence = "low"
		}
		if processComplete(meta) {
			report.add(Finding{Classification: ReportedNotObserved, Confidence: confidence, Reason: reason, ItemID: command.itemID, Command: command.command, AgentSeq: command.seq})
		} else {
			report.add(Finding{Classification: Unobservable, Reason: processCoverageReason(meta), ItemID: command.itemID, Command: command.command, AgentSeq: command.seq})
		}
	}

	infrastructure := infrastructureExecs(events, execs, commands, used, launchers)
	addUnmatchedFindings(&report, meta, execs, used, launchers, infrastructure)
	return report
}

func (r *Report) add(f Finding) {
	r.Findings = append(r.Findings, f)
	r.Counts[f.Classification]++
}

func collectCommands(events []storage.Event) []commandAction {
	byID := make(map[string]*commandAction)
	var order []*commandAction
	for _, ev := range events {
		if ev.Type != storage.TypeAgent {
			continue
		}
		var d model.AgentDetail
		if json.Unmarshal(ev.DataJSON, &d) != nil || d.Kind != "command_execution" || strings.TrimSpace(d.Command) == "" {
			continue
		}
		key := d.ItemID
		if key == "" {
			key = fmt.Sprintf("seq:%d", ev.Seq)
		}
		a := byID[key]
		if a == nil {
			a = &commandAction{itemID: d.ItemID, command: d.Command, status: d.Status, start: ev.TS, end: ev.TS, seq: ev.Seq}
			byID[key] = a
			order = append(order, a)
		} else {
			a.end = ev.TS
			if d.Command != "" {
				a.command = d.Command
			}
			if d.Status != "" {
				a.status = d.Status
			}
		}
	}
	out := make([]commandAction, 0, len(order))
	for _, a := range order {
		out = append(out, *a)
	}
	return out
}

func collectExecs(events []storage.Event) []execEvent {
	var out []execEvent
	for _, ev := range events {
		if ev.Type != storage.TypeExec {
			continue
		}
		var d model.ExecDetail
		_ = json.Unmarshal(ev.DataJSON, &d)
		out = append(out, execEvent{ev: ev, detail: d, parent: -1})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ev.TS == out[j].ev.TS {
			return out[i].ev.Seq < out[j].ev.Seq
		}
		return out[i].ev.TS < out[j].ev.TS
	})
	lastByPID := make(map[int]int)
	generations := make(map[int]int)
	for i := range out {
		ex := &out[i]
		generations[ex.ev.PID]++
		ex.generation = generations[ex.ev.PID]
		if previous, ok := lastByPID[ex.ev.PID]; ok {
			// An exec replacement is the next generation of the same process,
			// not a reason to apply the previous generation's classification.
			ex.parent = previous
		} else if parent, ok := lastByPID[ex.ev.PPID]; ok && ex.ev.PPID > 0 {
			ex.parent = parent
		}
		lastByPID[ex.ev.PID] = i
	}
	return out
}

func launcherExecs(meta runs.Meta, events []storage.Event, execs []execEvent, commands []commandAction) map[int]bool {
	out := make(map[int]bool)
	want := "codex"
	if len(meta.CommandArgv) > 0 {
		want = filepath.Base(meta.CommandArgv[0])
	}
	boundary := agentLifecycleStart(events)
	if boundary == 0 && len(commands) > 0 {
		boundary = commands[0].start
	}
	if boundary == 0 {
		boundary = int64(^uint64(0) >> 1)
	}
	for i, ex := range execs {
		name := execName(ex.detail)
		if ex.ev.TS <= boundary && (name == want || name == "codex" || name == "node") {
			out[i] = true
		}
	}
	return out
}

func agentLifecycleStart(events []storage.Event) int64 {
	var fallback int64
	for _, ev := range events {
		if ev.Type != storage.TypeAgent {
			continue
		}
		var d model.AgentDetail
		if json.Unmarshal(ev.DataJSON, &d) != nil {
			continue
		}
		if fallback == 0 || ev.TS < fallback {
			fallback = ev.TS
		}
		if d.Kind == "turn_started" {
			return ev.TS
		}
	}
	return fallback
}

func bestCandidate(meta runs.Meta, action commandAction, execs []execEvent, used map[int]bool, excluded map[int]bool) (int, string, bool) {
	best, bestScore, bestDistance, ties := -1, 0, int64(^uint64(0)>>1), 0
	const skew = int64(5_000_000_000)
	for i, ex := range execs {
		if used[i] || excluded[i] || ex.ev.TS < action.start-skew || ex.ev.TS > action.end+skew {
			continue
		}
		score := matchScore(meta, action.command, ex.detail)
		if score == 0 {
			continue
		}
		distance := lifecycleDistance(ex.ev.TS, action.start, action.end)
		if score > bestScore || (score == bestScore && distance < bestDistance) {
			best, bestScore, bestDistance, ties = i, score, distance, 1
		} else if score == bestScore && distance == bestDistance {
			ties++
		}
	}
	confidence := "low"
	if bestScore >= 90 {
		confidence = "high"
	} else if bestScore >= 60 {
		confidence = "medium"
	}
	return best, confidence, ties > 1
}

func lifecycleDistance(ts, start, end int64) int64 {
	if ts < start {
		return start - ts
	}
	if ts > end {
		return ts - end
	}
	return 0
}

func attributeEpisode(action commandAction, anchor int, execs []execEvent, used map[int]bool) int {
	const skew = int64(5_000_000_000)
	windowStart, windowEnd := action.start-skew, action.end+skew
	episode := map[int]bool{anchor: true}

	// Expand deterministically through observed exec-generation ancestry.
	// Descendants belong to the action. Ancestors are included only when they
	// are recognizable wrappers, avoiding ownership by PID alone.
	changed := true
	for changed {
		changed = false
		for i, ex := range execs {
			if used[i] || episode[i] || ex.ev.TS < windowStart || ex.ev.TS > windowEnd {
				continue
			}
			if ex.parent >= 0 && episode[ex.parent] {
				episode[i] = true
				changed = true
				continue
			}
			if isExecutionWrapper(ex.detail) && episodeHasChild(episode, execs, i) {
				episode[i] = true
				changed = true
			}
		}
	}

	for i := range episode {
		used[i] = true
	}
	return len(episode)
}

func episodeHasChild(episode map[int]bool, execs []execEvent, parent int) bool {
	for i := range episode {
		if execs[i].parent == parent {
			return true
		}
	}
	return false
}

func infrastructureExecs(events []storage.Event, execs []execEvent, commands []commandAction, used, launchers map[int]bool) map[int]bool {
	infra := make(map[int]bool)
	for i := range launchers {
		infra[i] = true
	}

	startupBoundary := int64(0)
	if len(commands) > 0 {
		startupBoundary = commands[0].start
	} else {
		// A no-command turn still performs substantial Codex harness setup. Use
		// the structured runtime lifecycle boundary rather than interpreting each
		// setup exec as an unreported action. The observations remain in storage.
		startupBoundary = agentLifecycleEnd(events)
	}
	if startupBoundary == 0 {
		return infra
	}

	startupSignatures := make(map[string]bool)
	for i, ex := range execs {
		if used[i] || launchers[i] || ex.ev.TS >= startupBoundary {
			continue
		}
		infra[i] = true
		startupSignatures[execSignature(ex.detail)] = true
	}

	// Runtime probes commonly repeat after the first command is reported.
	// Classify by a signature learned from startup, not by a command-name list.
	for i, ex := range execs {
		if used[i] || launchers[i] || infra[i] {
			continue
		}
		if startupSignatures[execSignature(ex.detail)] || isCodexRuntimeExecutable(ex.detail) {
			infra[i] = true
		}
	}
	return infra
}

func agentLifecycleEnd(events []storage.Event) int64 {
	var end int64
	for _, ev := range events {
		if ev.Type != storage.TypeAgent {
			continue
		}
		var d model.AgentDetail
		if json.Unmarshal(ev.DataJSON, &d) != nil {
			continue
		}
		if ev.TS > end {
			end = ev.TS
		}
		if d.Kind == "turn_completed" {
			return ev.TS
		}
	}
	return end
}

func addUnmatchedFindings(report *Report, meta runs.Meta, execs []execEvent, used, launchers, infrastructure map[int]bool) {
	unmatched := make(map[int]bool)
	for i := range execs {
		if !used[i] && !launchers[i] && !infrastructure[i] {
			unmatched[i] = true
		}
	}
	if len(unmatched) == 0 {
		return
	}

	groups := make(map[int][]int)
	for i := range unmatched {
		root := i
		seen := make(map[int]bool)
		for execs[root].parent >= 0 && unmatched[execs[root].parent] && !seen[root] {
			seen[root] = true
			root = execs[root].parent
		}
		groups[root] = append(groups[root], i)
	}

	roots := make([]int, 0, len(groups))
	for root := range groups {
		roots = append(roots, root)
	}
	sort.Slice(roots, func(i, j int) bool { return execs[roots[i]].ev.TS < execs[roots[j]].ev.TS })

	incompleteCount := 0
	incompleteSample := -1
	for _, root := range roots {
		ex := execs[root]
		ancestryComplete := ex.parent >= 0 || (ex.ev.PPID > 0 && parentPIDObserved(execs, ex.ev.PPID, ex.ev.TS))
		if !ancestryComplete {
			incompleteCount += len(groups[root])
			if incompleteSample < 0 {
				incompleteSample = root
			}
			continue
		}
		f := Finding{Confidence: "medium", ExecSeq: ex.ev.Seq, PID: ex.ev.PID, ExecSummary: ex.ev.Summary}
		if comparisonComplete(meta) {
			f.Classification = ObservedNotReported
			f.Reason = fmt.Sprintf("kernel-observed process subtree (%d exec observation(s)) has no correlated Codex runtime command", len(groups[root]))
		} else {
			f.Classification = Unobservable
			f.Reason = comparisonCoverageReason(meta)
		}
		report.add(f)
	}

	if incompleteCount > 0 {
		ex := execs[incompleteSample]
		report.add(Finding{
			Classification: Unobservable,
			Confidence:     "medium",
			Reason:         fmt.Sprintf("process ancestry incomplete for %d unmatched exec observation(s); aggregated into one finding", incompleteCount),
			ExecSeq:        ex.ev.Seq,
			PID:            ex.ev.PID,
			ExecSummary:    ex.ev.Summary,
		})
	}
}

func parentPIDObserved(execs []execEvent, pid int, before int64) bool {
	for _, ex := range execs {
		if ex.ev.TS > before {
			break
		}
		if ex.ev.PID == pid {
			return true
		}
	}
	return false
}

func execName(d model.ExecDetail) string {
	if len(d.Argv) > 0 && strings.TrimSpace(d.Argv[0]) != "" {
		return filepath.Base(d.Argv[0])
	}
	return filepath.Base(d.Filename)
}

func execSignature(d model.ExecDetail) string {
	if len(d.Argv) > 0 {
		return loose(canonicalArgv(d.Argv))
	}
	return loose(filepath.Base(d.Filename))
}

func isCodexRuntimeExecutable(d model.ExecDetail) bool {
	name := strings.ToLower(execName(d))
	return name == "codex" || name == "node" || strings.HasPrefix(name, "codex-")
}

func isExecutionWrapper(d model.ExecDetail) bool {
	name := strings.ToLower(execName(d))
	switch name {
	case "sh", "bash", "dash", "zsh", "bwrap", "bubblewrap", "codex-linux-sandbox", "sandbox-exec":
		return true
	default:
		return strings.Contains(name, "sandbox")
	}
}

func matchScore(meta runs.Meta, command string, d model.ExecDetail) int {
	if score := commandIdentityScore(command, d); score > 0 {
		if score >= 90 {
			return score
		}
	}
	argv := d.Argv
	if len(argv) == 0 && d.Filename != "" {
		argv = []string{d.Filename}
	}
	observed := canonicalArgv(argv)
	reported := canonicalCommand(command)
	reportedFields, observedFields := strings.Fields(reported), strings.Fields(observed)
	if len(reportedFields) == 0 || len(observedFields) == 0 || reportedFields[0] != observedFields[0] {
		return 0
	}
	if orderedContains(observedFields, reportedFields) {
		score := 60
		if d.CWD == "" || samePath(meta.CWD, d.CWD) {
			score += 10
		}
		return score
	}
	return 30
}

func commandIdentityScore(command string, d model.ExecDetail) int {
	argv := d.Argv
	if len(argv) == 0 && d.Filename != "" {
		argv = []string{d.Filename}
	}
	if len(argv) == 0 {
		return 0
	}

	reported := canonicalCommand(command)
	observed := canonicalArgv(argv)
	if reported == observed || loose(reported) == loose(observed) {
		return 100
	}

	// Shell quoting is not preserved identically by the runtime JSON and the
	// kernel argv observation. Compare the payloads after quote normalization.
	if reportedPayload, observedPayload := shellCommandPayload(command), shellPayload(argv); reportedPayload != "" && observedPayload != "" && loose(reportedPayload) == loose(observedPayload) {
		return 100
	}
	if reportedPayload := shellCommandPayload(command); reportedPayload != "" && loose(reportedPayload) == loose(observed) {
		return 95
	}
	if observedPayload := shellPayload(argv); observedPayload != "" && loose(observedPayload) == loose(reported) {
		return 95
	}

	// Infrastructure wrappers commonly place the real argv after their own
	// options (often after "--"). Match a complete argv suffix only; this does
	// not interpret the wrapper's policy or intent.
	for start := 1; start < len(argv); start++ {
		candidate := canonicalArgv(argv[start:])
		if candidate == reported || loose(candidate) == loose(reported) {
			return 90
		}
	}
	return 0
}

func canonicalArgv(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	copyArgv := append([]string(nil), argv...)
	copyArgv[0] = filepath.Base(copyArgv[0])
	return canonical(strings.Join(copyArgv, " "))
}

func canonicalCommand(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) == 0 {
		return ""
	}
	fields[0] = filepath.Base(fields[0])
	return canonical(strings.Join(fields, " "))
}

func canonical(s string) string { return strings.Join(strings.Fields(strings.TrimSpace(s)), " ") }
func loose(s string) string {
	return canonical(strings.Map(func(r rune) rune {
		if r == '\'' || r == '"' || r == '\\' {
			return -1
		}
		if unicode.IsSpace(r) {
			return ' '
		}
		return unicode.ToLower(r)
	}, s))
}

func shellPayload(argv []string) string {
	if len(argv) < 3 {
		return ""
	}
	name := filepath.Base(argv[0])
	if name != "sh" && name != "bash" && name != "dash" && name != "zsh" {
		return ""
	}
	for i := 1; i < len(argv)-1; i++ {
		if argv[i] == "-c" || argv[i] == "-lc" {
			return argv[i+1]
		}
	}
	return ""
}

func shellCommandPayload(command string) string {
	fields := strings.Fields(strings.TrimSpace(command))
	if len(fields) < 3 {
		return ""
	}
	name := filepath.Base(fields[0])
	if name != "sh" && name != "bash" {
		return ""
	}
	for i := 1; i < len(fields)-1; i++ {
		if fields[i] == "-c" || fields[i] == "-lc" {
			return strings.Join(fields[i+1:], " ")
		}
	}
	return ""
}

func orderedContains(haystack, needle []string) bool {
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if strings.Join(haystack[i:i+len(needle)], " ") == strings.Join(needle, " ") {
			return true
		}
	}
	return false
}

func samePath(a, b string) bool {
	aa, ea := filepath.Abs(a)
	bb, eb := filepath.Abs(b)
	return ea == nil && eb == nil && filepath.Clean(aa) == filepath.Clean(bb)
}

func processComplete(meta runs.Meta) bool {
	return meta.Coverage.Process.Availability == "available" && meta.Coverage.Process.Capture == "complete"
}

func comparisonComplete(meta runs.Meta) bool {
	return processComplete(meta) && meta.Coverage.Agent.Capture == "complete" && meta.Coverage.Agent.Interpretation == "complete"
}

func processCoverageReason(meta runs.Meta) string {
	p := meta.Coverage.Process
	if p.Availability != "available" {
		return "process observation unavailable"
	}
	if p.Capture != "complete" {
		return fmt.Sprintf("process capture incomplete: %d exec event(s) lost within Logira (collector-forward=%d, session-queue=%d, persistence=%d)",
			p.KnownLoss.Total(), p.KnownLoss.CollectorForwardDropped, p.KnownLoss.SessionQueueDropped, p.KnownLoss.PersistenceFailures)
	}
	return "process observation state unknown"
}

func comparisonCoverageReason(meta runs.Meta) string {
	if !processComplete(meta) {
		return processCoverageReason(meta)
	}
	if meta.Coverage.Agent.Capture != "complete" {
		return "agent runtime capture incomplete"
	}
	if meta.Coverage.Agent.Interpretation != "complete" {
		return "agent runtime events captured, but some schemas were not interpreted"
	}
	return "comparison coverage incomplete"
}
