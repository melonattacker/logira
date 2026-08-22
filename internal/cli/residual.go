package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func ResidualCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("residual", args, residualUsage)
	var asJSON bool
	var effects bool
	var verbose bool
	fs.BoolVar(&asJSON, "json", false, "emit the report as JSON")
	fs.BoolVar(&effects, "effects", false, "inspect effects inside matched execution episodes")
	fs.BoolVar(&verbose, "verbose", false, "show every execution-episode member and attributed effect (requires --effects)")
	sel := "last"
	parseArgs := args
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		sel = args[0]
		parseArgs = args[1:]
	}
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("residual accepts at most one run selector")
	}
	if fs.NArg() == 1 {
		if sel != "last" {
			return fmt.Errorf("residual accepts at most one run selector")
		}
		sel = fs.Arg(0)
	}
	if verbose && !effects {
		return fmt.Errorf("--verbose requires --effects")
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	runID, runDir, err := runs.ResolveRunID(home, sel)
	if err != nil {
		return err
	}
	meta, err := runs.ReadMeta(runDir)
	if err != nil {
		return fmt.Errorf("read run metadata: %w", err)
	}
	if meta.EndTS == 0 {
		return fmt.Errorf("run %s is still running; residual analysis requires a completed run", runID)
	}
	if meta.AgentProvider == "" {
		return fmt.Errorf("run %s has no agent runtime telemetry; use 'logira run --agent codex -- codex exec --json ...'", runID)
	}
	if meta.AgentProvider != "codex" {
		return fmt.Errorf("run %s uses unsupported agent provider %q", runID, meta.AgentProvider)
	}

	events, err := readResidualEvents(runID, runDir)
	if err != nil {
		return err
	}
	report := residual.Analyze(meta, events)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Meta   runs.Meta       `json:"meta"`
			Report residual.Report `json:"report"`
		}{Meta: meta, Report: report})
	}
	renderResidual(meta, report, effects, verbose)
	return nil
}

func readResidualEvents(runID, runDir string) ([]storage.Event, error) {
	events, err := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read run events: %w", err)
	}
	return storage.Filter(events, storage.QueryOptions{RunID: runID}), nil
}

func renderResidual(meta runs.Meta, report residual.Report, effects, verbose bool) {
	stdoutf("Action Residual: %s\n", report.RunID)
	stdoutf("  comparison: Codex runtime reports vs kernel-observed activity\n")
	stdoutf("  agent:      capture=%s interpretation=%s lines=%d/%d unknown=%d malformed=%d raw_truncated=%d append_failures=%d\n",
		meta.Coverage.Agent.Capture, meta.Coverage.Agent.Interpretation,
		meta.Coverage.Agent.LinesPersisted, meta.Coverage.Agent.LinesSeen,
		meta.Coverage.Agent.UnknownSchema, meta.Coverage.Agent.Malformed,
		meta.Coverage.Agent.RawTruncated, meta.Coverage.Agent.AppendFailures)
	renderKernelCoverage("process", meta.Coverage.Process)
	renderKernelCoverage("file", meta.Coverage.File)
	renderKernelCoverage("network", meta.Coverage.Network)
	stdoutf("  sandbox:    availability=%s\n", meta.Coverage.SandboxDecisions.Availability)

	stdoutln("\nFindings:")
	if len(report.Findings) == 0 {
		stdoutln("(none)")
	}
	for _, f := range report.Findings {
		label := string(f.Classification)
		if f.Confidence != "" {
			label += " confidence=" + f.Confidence
		}
		stdoutf("- %s\n", label)
		if f.Command != "" {
			stdoutf("  reported: %s", f.Command)
			if f.ItemID != "" {
				stdoutf(" (item=%s)", f.ItemID)
			}
			stdoutln()
		}
		if f.ExecSummary != "" {
			stdoutf("  observed: %s (pid=%d seq=%d)\n", f.ExecSummary, f.PID, f.ExecSeq)
		}
		if f.Reason != "" {
			stdoutf("  reason:   %s\n", f.Reason)
		}
		if effects && f.Classification == residual.Matched {
			if episode := findEpisode(report.Episodes, f.ExecSeq); episode != nil {
				renderExecutionEpisode(*episode, verbose)
			}
		}
	}

	stdoutln("\nTotals:")
	for _, class := range []residual.Classification{
		residual.Matched,
		residual.ReportedNotObserved,
		residual.ObservedNotReported,
		residual.Blocked,
		residual.Unobservable,
	} {
		stdoutf("  %-24s %d\n", class, report.Counts[class])
	}
	stdoutln("\nThese findings describe observational consistency; they are not an intent, safety, or maliciousness score.")
}

func findEpisode(episodes []residual.ExecutionEpisode, execSeq int64) *residual.ExecutionEpisode {
	for i := range episodes {
		if episodes[i].DirectMatch.Seq == execSeq {
			return &episodes[i]
		}
	}
	return nil
}

type episodeExecGroup struct {
	Role    residual.ExecMemberRole
	Summary string
	Count   int
}

func compactEpisodeExecGroups(episode residual.ExecutionEpisode, limit int) ([]episodeExecGroup, int) {
	groups := make([]episodeExecGroup, 0)
	indexes := make(map[string]int)
	transitiveCount := 0
	for _, member := range episode.ExecMembers {
		if member.Role == residual.ExecRoleDirectMatch || member.Role == residual.ExecRoleWrapper {
			continue
		}
		transitiveCount++
		display := episodeExecDisplay(member)
		key := string(member.Role) + "\x00" + display
		if index, ok := indexes[key]; ok {
			groups[index].Count++
			continue
		}
		indexes[key] = len(groups)
		groups = append(groups, episodeExecGroup{Role: member.Role, Summary: display, Count: 1})
	}
	if limit <= 0 || len(groups) <= limit {
		return groups, 0
	}
	shownMembers := 0
	for _, group := range groups[:limit] {
		shownMembers += group.Count
	}
	return groups[:limit], transitiveCount - shownMembers
}

func renderExecutionEpisode(episode residual.ExecutionEpisode, verbose bool) {
	ancestry := "complete"
	if !episode.AncestryComplete {
		ancestry = "incomplete"
	}
	stdoutf("  episode:  execs=%d wrappers=%d transitive=%d files=%d network=%d process_capture=%s ancestry=%s\n",
		episode.Summary.Execs, episode.Summary.Wrappers, episode.Summary.TransitiveExecs, episode.Summary.Files,
		episode.Summary.Networks, episode.ProcessCapture, ancestry)

	if verbose {
		stdoutln("  episode execs:")
		for _, member := range episode.ExecMembers {
			parent := ""
			if member.ParentExecSeq > 0 {
				parent = fmt.Sprintf(" parent_seq=%d", member.ParentExecSeq)
			}
			display := member.Summary
			if member.Role != residual.ExecRoleWrapper {
				display = episodeExecDisplay(member)
			}
			stdoutf("    [%s] seq=%d pid=%d gen=%d%s %s\n", member.Role, member.Seq, member.PID, member.Generation, parent, display)
		}
	} else {
		wrappers := episodeMembersByRole(episode, residual.ExecRoleWrapper)
		if len(wrappers) > 0 {
			stdoutln("  execution wrappers:")
			limit := min(3, len(wrappers))
			for _, member := range wrappers[:limit] {
				stdoutf("    %s\n", cliui.Truncate(member.Summary, 120))
			}
			if limit < len(wrappers) {
				stdoutf("    ... %d more wrapper observation(s); use --verbose\n", len(wrappers)-limit)
			}
		}
	}
	if !verbose && episode.Summary.TransitiveExecs > 0 {
		groups, omitted := compactEpisodeExecGroups(episode, 8)
		stdoutln("  transitive execs:")
		for _, group := range groups {
			count := ""
			if group.Count > 1 {
				count = fmt.Sprintf(" (x%d)", group.Count)
			}
			stdoutf("    [%s] %s%s\n", group.Role, cliui.Truncate(group.Summary, 120), count)
		}
		if omitted > 0 {
			stdoutf("    ... %d more transitive exec observation(s); use --verbose\n", omitted)
		}
	}

	renderEpisodeFileEffects(episode.FileEffects, verbose)
	renderEpisodeNetworkEffects(episode.NetworkEffects, verbose)
	for _, issue := range episode.AttributionIssues {
		stdoutf("  attribution: %s\n", issue)
	}
}

func episodeExecDisplay(member residual.ExecMember) string {
	filename := strings.TrimSpace(member.Filename)
	if filename == "" {
		return member.Summary
	}
	parts := []string{"exec", filename}
	if len(member.Argv) > 1 {
		parts = append(parts, member.Argv[1:]...)
	}
	return strings.Join(parts, " ")
}

func episodeMembersByRole(episode residual.ExecutionEpisode, role residual.ExecMemberRole) []residual.ExecMember {
	out := make([]residual.ExecMember, 0)
	for _, member := range episode.ExecMembers {
		if member.Role == role {
			out = append(out, member)
		}
	}
	return out
}

func renderEpisodeFileEffects(effects []residual.FileEffect, verbose bool) {
	if len(effects) == 0 {
		return
	}
	counts := make(map[string]int)
	for _, effect := range effects {
		op := effect.Op
		if op == "" {
			op = "unknown"
		}
		counts[op]++
	}
	stdoutf("  file effects: %s\n", formatEffectCounts(counts))
	ordered := append([]residual.FileEffect(nil), effects...)
	sort.SliceStable(ordered, func(i, j int) bool {
		return fileEffectDisplayPriority(ordered[i].Op) < fileEffectDisplayPriority(ordered[j].Op)
	})
	limit := 5
	if verbose || len(ordered) < limit {
		limit = len(ordered)
	}
	for _, effect := range ordered[:limit] {
		stdoutf("    seq=%d pid=%d via_exec=%d %s %s\n", effect.Seq, effect.PID, effect.ProcessExecSeq, emptyAs(effect.Op, "unknown"), cliui.Truncate(effect.Path, 120))
	}
	if limit < len(ordered) {
		stdoutf("    ... %d more file effect(s); use --verbose\n", len(ordered)-limit)
	}
}

func fileEffectDisplayPriority(op string) int {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "open", "read", "access":
		return 1
	default:
		return 0
	}
}

func renderEpisodeNetworkEffects(effects []residual.NetworkEffect, verbose bool) {
	if len(effects) == 0 {
		return
	}
	counts := make(map[string]int)
	for _, effect := range effects {
		op := effect.Op
		if op == "" {
			op = "unknown"
		}
		counts[op]++
	}
	stdoutf("  network effects: %s\n", formatEffectCounts(counts))
	limit := 5
	if verbose || len(effects) < limit {
		limit = len(effects)
	}
	for _, effect := range effects[:limit] {
		dst := effect.DstIP
		if effect.DstPort > 0 {
			dst = fmt.Sprintf("%s:%d", dst, effect.DstPort)
		}
		stdoutf("    seq=%d pid=%d via_exec=%d %s %s %s bytes=%d\n", effect.Seq, effect.PID, effect.ProcessExecSeq,
			emptyAs(effect.Op, "unknown"), emptyAs(effect.Proto, "unknown"), dst, effect.Bytes)
	}
	if limit < len(effects) {
		stdoutf("    ... %d more network effect(s); use --verbose\n", len(effects)-limit)
	}
}

func formatEffectCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return strings.Join(parts, " ")
}

func emptyAs(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func renderKernelCoverage(name string, coverage runs.KernelCoverage) {
	loss := coverage.KnownLoss
	stdoutf("  %-11s availability=%s capture=%s loss={collector_forward:%d session_queue:%d persistence:%d}\n",
		name+":", coverage.Availability, coverage.Capture,
		loss.CollectorForwardDropped, loss.SessionQueueDropped, loss.PersistenceFailures)
}

func residualUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	_, _ = fmt.Fprintf(w, "%s residual: compare Codex runtime reports with kernel-observed actions\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s residual [last|<run-id>] [--effects [--verbose]] [--json]\n\n", prog)
	_, _ = fmt.Fprintln(w, "Notes:")
	_, _ = fmt.Fprintln(w, "  Only completed runs captured with --agent codex are supported in v0.")
	_, _ = fmt.Fprintln(w, "  Results measure observational consistency, not model or user intent.")
	_, _ = fmt.Fprintln(w, "  --effects shows causally attributed episode contents; it does not classify semantic legitimacy.")
	_, _ = fmt.Fprintln(w, "  Kernel capture 'complete' means Logira knows of no loss after its collector boundary.")
	_, _ = fmt.Fprintln(w, "  It does not prove that the underlying kernel/BPF path was globally lossless.")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
