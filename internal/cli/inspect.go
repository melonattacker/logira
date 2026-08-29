package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/runs"
)

func InspectCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("inspect", args, inspectUsage)
	var asJSON, verbose, noColor bool
	var colorS string
	var limit int
	fs.BoolVar(&asJSON, "json", false, "emit structured JSON")
	fs.BoolVar(&verbose, "verbose", false, "show all retained episode evidence and identifiers")
	fs.BoolVar(&noColor, "no-color", false, "disable ANSI colors")
	fs.StringVar(&colorS, "color", "auto", "color mode: auto|always|never")
	fs.IntVar(&limit, "limit", 10, "max evidence rows per section (ignored by --verbose)")

	sel, target := "last", ""
	parseArgs := args
	if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		sel = parseArgs[0]
		parseArgs = parseArgs[1:]
		if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
			target = parseArgs[0]
			parseArgs = parseArgs[1:]
		}
	}
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	remaining := fs.Args()
	if target == "" && len(remaining) > 0 {
		if sel == "last" && len(remaining) > 1 {
			sel = remaining[0]
			remaining = remaining[1:]
		}
		if len(remaining) > 0 {
			target = remaining[0]
			remaining = remaining[1:]
		}
	}
	if len(remaining) > 0 {
		return fmt.Errorf("inspect accepts one run selector and one target")
	}
	if target == "" {
		return fmt.Errorf("inspect requires an action target such as action:3")
	}
	if !strings.HasPrefix(target, "action:") || strings.TrimPrefix(target, "action:") == "" {
		return fmt.Errorf("unsupported inspect target %q (expected action:<ordinal-or-item-id>)", target)
	}
	if limit <= 0 {
		return fmt.Errorf("--limit must be greater than zero")
	}
	colorMode, err := cliui.ParseColorMode(colorS)
	if err != nil {
		return err
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
	if err := validateActionInspectionRun(meta, runID); err != nil {
		return err
	}
	events, err := readResidualEvents(runID, runDir)
	if err != nil {
		return err
	}
	view, err := actionview.Build(meta, events)
	if err != nil {
		return fmt.Errorf("build agent action view: %w", err)
	}
	action, err := view.ResolveAction(strings.TrimPrefix(target, "action:"))
	if err != nil {
		return fmt.Errorf("run %s: %w", runID, err)
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Meta   runs.Meta         `json:"meta"`
			Action actionview.Action `json:"action"`
		}{Meta: meta, Action: *action})
	}
	clr := cliui.NewColorizer(colorMode, noColor, os.Stdout)
	renderActionInspection(os.Stdout, meta, *action, limit, verbose, clr)
	return nil
}

func validateActionInspectionRun(meta runs.Meta, runID string) error {
	if meta.AgentProvider == "" {
		return fmt.Errorf("run %s has no supported agent runtime telemetry; action inspection requires 'logira run --agent codex -- codex exec --json ...'", runID)
	}
	if meta.AgentProvider != "codex" {
		return fmt.Errorf("run %s uses unsupported agent provider %q", runID, meta.AgentProvider)
	}
	if meta.EndTS == 0 {
		return fmt.Errorf("run %s is still running; action inspection requires a completed run", runID)
	}
	return nil
}

func renderActionInspection(w io.Writer, meta runs.Meta, action actionview.Action, limit int, verbose bool, clr cliui.Colorizer) {
	separator := strings.Repeat("─", 60)
	presentationWarnings := action.CoverageWarnings
	if action.Episode != nil {
		presentationWarnings = actionview.EpisodeWarnings(*action.Episode)
	}
	presentationWarnings = uniqueStrings(append(presentationWarnings, actionview.CoverageWarnings(meta)...))
	_, _ = fmt.Fprintf(w, "Action #%d\n%s\n\n", action.Index, separator)
	_, _ = fmt.Fprintln(w, "Runtime report")
	_, _ = fmt.Fprintf(w, "  command: %s\n", action.RuntimeReport.Command)
	_, _ = fmt.Fprintf(w, "  item:    %s\n", emptyAs(action.ItemID, "-"))
	_, _ = fmt.Fprintf(w, "  status:  %s\n", emptyAs(action.RuntimeReport.Status, "unknown"))
	if action.RuntimeReport.ExitCode != nil {
		_, _ = fmt.Fprintf(w, "  exit:    %d\n", *action.RuntimeReport.ExitCode)
	}
	if output := strings.TrimSpace(action.RuntimeReport.Text); output != "" {
		shown, truncated := truncateRuntimeOutput(output, verbose)
		_, _ = fmt.Fprintf(w, "\n%s\n", shown)
		if truncated {
			_, _ = fmt.Fprintln(w, "... runtime output truncated; use --verbose or --json")
		}
	}
	if action.RuntimeReport.RawTruncated {
		_, _ = fmt.Fprintln(w, "  note: the provider's retained raw record was truncated during ingestion")
	}

	_, _ = fmt.Fprintln(w, "\nCorrelation")
	correlation := actionClassificationLabel(action, clr)
	if action.Finding.Confidence != "" {
		correlation += " · " + action.Finding.Confidence + " confidence"
	}
	_, _ = fmt.Fprintf(w, "  %s\n", correlation)
	showReason := verbose || action.Finding.Classification != residual.Matched || action.Finding.Confidence != "high" || len(presentationWarnings) > 0
	if showReason && action.Finding.Reason != "" {
		_, _ = fmt.Fprintf(w, "  reason: %s\n", action.Finding.Reason)
	}

	if action.Episode != nil {
		_, _ = fmt.Fprintln(w, "\nExecution")
		renderExecForest(w, meta.CWD, action.RuntimeReport.Provider, *action.Episode, action.Detections, verbose)
		_, _ = fmt.Fprintln(w, "\nEffects")
		_, _ = fmt.Fprintf(w, "  Process  %d\n  File     %d\n  Network  %d\n",
			action.Episode.Summary.Processes, action.Episode.Summary.Files, action.Episode.Summary.Networks)
		renderInspectFileEffects(w, meta, *action.Episode, action.Detections, limit, verbose)
		renderInspectNetworkEffects(w, *action.Episode, action.Detections, limit, verbose)
	}

	_, _ = fmt.Fprintln(w, "\nDetections")
	if len(action.Detections) == 0 {
		_, _ = fmt.Fprintln(w, "  (none attributed to this action episode)")
	} else if verbose {
		for _, detection := range action.Detections {
			severity := strings.ToUpper(detection.Severity)
			if clr.Enabled {
				severity = clr.Severity(severity)
			}
			_, _ = fmt.Fprintf(w, "  %s %s %s\n", severity, detection.RuleID, detection.Message)
			_, _ = fmt.Fprintf(w, "    related event seq=%d", detection.RelatedEventSeq)
			if detection.RelatedEvent != nil {
				_, _ = fmt.Fprintf(w, " type=%s summary=%s", detection.RelatedEvent.Type, cliui.Truncate(detection.RelatedEvent.Summary, 80))
			}
			_, _ = fmt.Fprintln(w)
		}
	} else {
		renderInspectDetectionGroups(w, action.Detections, limit, clr)
	}

	_, _ = fmt.Fprintln(w, "\nTelemetry")
	_, _ = fmt.Fprintf(w, "  agent    capture=%s interpretation=%s\n", coverageValue(meta.Coverage.Agent.Capture), coverageValue(meta.Coverage.Agent.Interpretation))
	_, _ = fmt.Fprintf(w, "  process  %s\n  file     %s\n  network  %s\n",
		coverageValue(kernelCoverageState(meta.Coverage.Process)), coverageValue(kernelCoverageState(meta.Coverage.File)), coverageValue(kernelCoverageState(meta.Coverage.Network)))
	if action.Episode != nil {
		ancestry := "complete"
		if !action.Episode.AncestryComplete {
			ancestry = "incomplete"
		}
		_, _ = fmt.Fprintf(w, "  ancestry %s\n", ancestry)
	}
	for _, warning := range presentationWarnings {
		_, _ = fmt.Fprintf(w, "  ! %s\n", warning)
	}
	_, _ = fmt.Fprintln(w, "\nNext:")
	_, _ = fmt.Fprintf(w, "  %s query %s --type detection\n", progName(), meta.RunID)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func renderInspectDetectionGroups(w io.Writer, detections []actionview.Detection, limit int, clr cliui.Colorizer) {
	groups := actionview.GroupDetections(detections)
	shown := min(len(groups), limit)
	for _, group := range groups[:shown] {
		severity := strings.ToUpper(group.Severity)
		if clr.Enabled {
			severity = clr.Severity(severity)
		}
		count := ""
		if group.Count > 1 {
			count = fmt.Sprintf(" (x%d)", group.Count)
		}
		_, _ = fmt.Fprintf(w, "  %s %s %s%s\n", severity, group.RuleID, group.Message, count)
		_, _ = fmt.Fprintf(w, "    %s\n", detectionEvidenceSummary(group.Detections))
	}
	if shown < len(groups) {
		_, _ = fmt.Fprintf(w, "  ... %d more detection group(s); use --verbose or query --type detection\n", len(groups)-shown)
	}
}

func detectionEvidenceSummary(detections []actionview.Detection) string {
	counts := make(map[string]int)
	samples := make([]string, 0, 2)
	seenSamples := make(map[string]bool)
	for _, detection := range detections {
		kind := "unavailable"
		if detection.RelatedEvent != nil {
			kind = string(detection.RelatedEvent.Type)
			sample := strings.TrimSpace(detection.RelatedEvent.Summary)
			if sample != "" && !seenSamples[sample] && len(samples) < 2 {
				seenSamples[sample] = true
				samples = append(samples, cliui.Truncate(sample, 64))
			}
		}
		counts[kind]++
	}
	parts := make([]string, 0, len(counts))
	for _, kind := range []string{"exec", "file", "net", "process", "unavailable"} {
		if counts[kind] > 0 {
			parts = append(parts, fmt.Sprintf("%s %d", kind, counts[kind]))
		}
	}
	result := "evidence: " + strings.Join(parts, " · ")
	if len(samples) > 0 {
		result += "; sample: " + strings.Join(samples, " | ")
	}
	return result
}

func truncateRuntimeOutput(output string, verbose bool) (string, bool) {
	if verbose {
		return output, false
	}
	const maxLines, maxRunes = 40, 8192
	lines := strings.Split(output, "\n")
	truncated := false
	if len(lines) > maxLines {
		lines = lines[:maxLines]
		truncated = true
	}
	joined := strings.Join(lines, "\n")
	if utf8.RuneCountInString(joined) > maxRunes {
		runes := []rune(joined)
		joined = string(runes[:maxRunes])
		truncated = true
	}
	return joined, truncated
}

type execTreeNode struct {
	member   residual.ExecMember
	parent   *execTreeNode
	children []*execTreeNode
	hidden   bool
	infra    string
}

func renderExecForest(w io.Writer, workspaceRoot, provider string, episode residual.ExecutionEpisode, detections []actionview.Detection, verbose bool) {
	bySeq := make(map[int64]*execTreeNode, len(episode.ExecMembers))
	nodes := make([]*execTreeNode, 0, len(episode.ExecMembers))
	for _, member := range episode.ExecMembers {
		node := &execTreeNode{member: member}
		bySeq[member.Seq] = node
		nodes = append(nodes, node)
	}
	roots := make([]*execTreeNode, 0)
	for _, node := range nodes {
		if parent := bySeq[node.member.ParentExecSeq]; parent != nil && node.member.ParentExecSeq > 0 {
			node.parent = parent
			parent.children = append(parent.children, node)
		}
	}
	detected := make(map[int64]bool)
	for _, detection := range detections {
		detected[detection.RelatedEventSeq] = true
	}
	collapsed := 0
	if !verbose && strings.EqualFold(provider, "codex") {
		for _, node := range nodes {
			node.infra = codexInfrastructureKind(node, detected)
			if node.infra != "" {
				node.hidden = true
				collapsed++
			}
		}
	}
	if collapsed > 0 {
		_, _ = fmt.Fprintf(w, "  [Codex sandbox infrastructure: %d exec observation(s) collapsed]\n", collapsed)
	}

	// Rebuild only the presentation edges. Visible children are attached to the
	// nearest visible ancestor; the stored ParentExecSeq forest is untouched.
	for _, node := range nodes {
		node.children = nil
	}
	for _, node := range nodes {
		if node.hidden {
			continue
		}
		parent := node.parent
		for parent != nil && parent.hidden {
			parent = parent.parent
		}
		if parent == nil {
			roots = append(roots, node)
		} else {
			parent.children = append(parent.children, node)
		}
	}

	large := !verbose && len(nodes) > 20
	grouped := 0
	var render func(*execTreeNode, string, string)
	render = func(node *execTreeNode, prefix, connector string) {
		_, _ = fmt.Fprintf(w, "  %s%s%s\n", prefix, connector, execTreeLabel(workspaceRoot, node.member, detected[node.member.Seq], verbose))
		items := execTreeChildItems(node.children, detected, large)
		childPrefix := prefix
		switch connector {
		case "├─ ":
			childPrefix += "│  "
		case "└─ ":
			childPrefix += "   "
		}
		for i, item := range items {
			last := i == len(items)-1
			childConnector := "├─ "
			if last {
				childConnector = "└─ "
			}
			if item.groupCount > 0 {
				grouped += item.groupCount
				_, _ = fmt.Fprintf(w, "  %s%s%s ×%d  [%s]\n", childPrefix, childConnector,
					execDisplayName(workspaceRoot, item.node.member, false), item.groupCount, item.node.member.Role)
				continue
			}
			render(item.node, childPrefix, childConnector)
		}
	}
	for i, root := range roots {
		if i > 0 {
			_, _ = fmt.Fprintln(w, "  (additional root)")
		}
		render(root, "", "")
	}
	if large {
		if grouped > 0 {
			_, _ = fmt.Fprintf(w, "  %d exec observations total; %d repetitive leaf observations grouped; use --verbose for the original forest\n", len(nodes), grouped)
		} else {
			_, _ = fmt.Fprintf(w, "  %d exec observations total; use --verbose for full paths and identifiers\n", len(nodes))
		}
	}
	if !episode.AncestryComplete {
		_, _ = fmt.Fprintln(w, "  ? parent not observed for one or more episode members; no edge was inferred")
	}
}

type execTreeItem struct {
	node       *execTreeNode
	groupCount int
}

func execTreeChildItems(children []*execTreeNode, detected map[int64]bool, enabled bool) []execTreeItem {
	if !enabled {
		items := make([]execTreeItem, 0, len(children))
		for _, child := range children {
			items = append(items, execTreeItem{node: child})
		}
		return items
	}
	counts := make(map[string]int)
	for _, child := range children {
		if key := execLeafGroupKey(child, detected); key != "" {
			counts[key]++
		}
	}
	emitted := make(map[string]bool)
	items := make([]execTreeItem, 0, len(children))
	for _, child := range children {
		key := execLeafGroupKey(child, detected)
		if key == "" || counts[key] < 3 {
			items = append(items, execTreeItem{node: child})
			continue
		}
		if emitted[key] {
			continue
		}
		emitted[key] = true
		items = append(items, execTreeItem{node: child, groupCount: counts[key]})
	}
	return items
}

func execLeafGroupKey(node *execTreeNode, detected map[int64]bool) string {
	if node == nil || len(node.children) > 0 || detected[node.member.Seq] || node.member.Role != residual.ExecRoleDescendant {
		return ""
	}
	filename := strings.TrimSpace(node.member.Filename)
	if filename == "" {
		return ""
	}
	return string(node.member.Role) + "\x00" + filepath.Clean(filename)
}

func codexInfrastructureKind(node *execTreeNode, detected map[int64]bool) string {
	if node == nil || detected[node.member.Seq] || node.member.Role == residual.ExecRoleDirectMatch || strings.TrimSpace(node.member.Filename) == "" {
		return ""
	}
	base := strings.ToLower(filepath.Base(filepath.Clean(node.member.Filename)))
	switch base {
	case "codex-linux-sandbox":
		return "launcher"
	case "bwrap":
		if hasCodexInfrastructureAncestor(node.parent) {
			return "bwrap"
		}
	case "true":
		if node.parent != nil && node.parent.infra == "bwrap" {
			return "probe"
		}
	case "codex":
		if node.member.Role == residual.ExecRoleWrapper && len(node.member.Argv) > 0 &&
			strings.EqualFold(filepath.Base(filepath.Clean(node.member.Argv[0])), "codex-linux-sandbox") && hasCodexInfrastructureAncestor(node.parent) {
			return "wrapper"
		}
	}
	return ""
}

func hasCodexInfrastructureAncestor(node *execTreeNode) bool {
	for ; node != nil; node = node.parent {
		if node.infra == "launcher" || node.infra == "bwrap" || node.infra == "wrapper" {
			return true
		}
	}
	return false
}

func execTreeLabel(workspaceRoot string, member residual.ExecMember, detected, verbose bool) string {
	name := execDisplayName(workspaceRoot, member, true)
	name = cliui.Truncate(name, 100)
	if detected {
		name = "⚠ " + name
	}
	name += fmt.Sprintf("  [%s]", member.Role)
	if verbose {
		name += fmt.Sprintf(" seq=%d pid=%d gen=%d", member.Seq, member.PID, member.Generation)
		if member.ParentExecSeq > 0 {
			name += fmt.Sprintf(" parent_seq=%d", member.ParentExecSeq)
		}
		if member.CWD != "" {
			name += " cwd=" + member.CWD
		}
		if strings.TrimSpace(member.Filename) != "" {
			name += " exe=" + filepath.Clean(member.Filename)
		}
	}
	return name
}

func execDisplayName(workspaceRoot string, member residual.ExecMember, includeArgs bool) string {
	name := strings.TrimSpace(member.Filename)
	if name != "" {
		filename := filepath.Clean(name)
		name = filepath.Base(filename)
		if qualifier := executableQualifier(workspaceRoot, filename); qualifier != "" {
			name += " (" + qualifier + ")"
		}
		if includeArgs && len(member.Argv) > 1 {
			name += " " + strings.Join(member.Argv[1:], " ")
		}
	} else {
		name = strings.TrimSpace(strings.TrimPrefix(member.Summary, "exec "))
	}
	return name
}

func executableQualifier(workspaceRoot, filename string) string {
	if !filepath.IsAbs(filename) {
		if strings.ContainsRune(filename, os.PathSeparator) {
			return filename
		}
		return ""
	}
	if rel, inside := displayWorkspacePath(workspaceRoot, filename); inside {
		return rel
	}
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/nix/store", "/snap"} {
		if filename == root || strings.HasPrefix(filename, root+string(os.PathSeparator)) {
			return ""
		}
	}
	return filename
}

type fileEffectGroup struct {
	Op, Path              string
	Count                 int
	Detection, Workspace  bool
	AttributionIncomplete bool
	Priority              int
}

func renderInspectFileEffects(w io.Writer, meta runs.Meta, episode residual.ExecutionEpisode, detections []actionview.Detection, limit int, verbose bool) {
	if len(episode.FileEffects) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nWorkspace and file effects")
	detected := detectionSeqSet(detections)
	if verbose {
		for _, effect := range episode.FileEffects {
			path, _ := displayWorkspacePath(meta.CWD, effect.Path)
			_, _ = fmt.Fprintf(w, "  %-11s %s  seq=%d pid=%d via_exec=%d attribution=%s\n",
				normalizeFileOp(effect.Op), path, effect.Seq, effect.PID, effect.ProcessExecSeq, effect.Attribution)
		}
		return
	}
	groupsByKey := make(map[string]*fileEffectGroup)
	for _, effect := range episode.FileEffects {
		op := normalizeFileOp(effect.Op)
		path, workspace := displayWorkspacePath(meta.CWD, effect.Path)
		key := op + "\x00" + path
		group := groupsByKey[key]
		if group == nil {
			group = &fileEffectGroup{Op: op, Path: path, Workspace: workspace}
			groupsByKey[key] = group
		}
		group.Count++
		group.Detection = group.Detection || detected[effect.Seq]
		group.AttributionIncomplete = group.AttributionIncomplete || effect.Attribution != "task_instance_latest_exec_generation"
	}
	groups := make([]*fileEffectGroup, 0, len(groupsByKey))
	for _, group := range groupsByKey {
		group.Priority = fileEffectPriority(group)
		groups = append(groups, group)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].Priority != groups[j].Priority {
			return groups[i].Priority < groups[j].Priority
		}
		if groups[i].Op != groups[j].Op {
			return groups[i].Op < groups[j].Op
		}
		return groups[i].Path < groups[j].Path
	})
	shown := len(groups)
	if shown > limit {
		shown = limit
	}
	for _, group := range groups[:shown] {
		marker, count := " ", ""
		if group.Detection {
			marker = "⚠"
		}
		if group.Count > 1 {
			count = fmt.Sprintf(" (x%d)", group.Count)
		}
		_, _ = fmt.Fprintf(w, "  %s %-11s %s%s\n", marker, group.Op, group.Path, count)
	}
	if shown < len(groups) {
		counts := make(map[string]int)
		for _, group := range groups[shown:] {
			counts[group.Op] += group.Count
		}
		_, _ = fmt.Fprintf(w, "  ... %d grouped effect(s) omitted: %s; use --verbose\n", len(groups)-shown, formatEffectCounts(counts))
	}
}

func normalizeFileOp(op string) string {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "create":
		return "CREATE"
	case "create_or_open":
		return "CREATE/OPEN"
	case "modify", "truncate":
		return "MODIFY"
	case "rename":
		return "RENAME"
	case "delete":
		return "DELETE"
	case "open", "read", "access":
		return "READ/OPEN"
	case "chdir":
		return "CHDIR"
	case "":
		return "UNKNOWN"
	default:
		return strings.ToUpper(strings.TrimSpace(op))
	}
}

func fileEffectPriority(group *fileEffectGroup) int {
	if group.Detection {
		return 0
	}
	stateChanging := group.Op == "CREATE" || group.Op == "CREATE/OPEN" || group.Op == "MODIFY" || group.Op == "RENAME" || group.Op == "DELETE"
	if group.Workspace && stateChanging {
		return 1
	}
	if group.AttributionIncomplete {
		return 2
	}
	if stateChanging {
		return 3
	}
	return 4
}

func displayWorkspacePath(cwd, path string) (string, bool) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || path == "" {
		return path, false
	}
	if !filepath.IsAbs(path) {
		return path, strings.TrimSpace(cwd) != ""
	}
	if strings.TrimSpace(cwd) == "" {
		return path, false
	}
	rel, err := filepath.Rel(filepath.Clean(cwd), path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return path, false
	}
	return rel, true
}

type networkEffectGroup struct {
	Op, Proto, Destination string
	Count                  int
	Bytes                  int64
	Detection              bool
}

func renderInspectNetworkEffects(w io.Writer, episode residual.ExecutionEpisode, detections []actionview.Detection, limit int, verbose bool) {
	if len(episode.NetworkEffects) == 0 {
		return
	}
	_, _ = fmt.Fprintln(w, "\nNetwork destinations")
	detected := detectionSeqSet(detections)
	if verbose {
		for _, effect := range episode.NetworkEffects {
			_, _ = fmt.Fprintf(w, "  %s %s %s bytes=%d seq=%d pid=%d via_exec=%d attribution=%s\n",
				emptyAs(effect.Op, "unknown"), emptyAs(effect.Proto, "unknown"), networkDestination(effect), effect.Bytes,
				effect.Seq, effect.PID, effect.ProcessExecSeq, effect.Attribution)
		}
		return
	}
	byKey := make(map[string]*networkEffectGroup)
	for _, effect := range episode.NetworkEffects {
		dst := networkDestination(effect)
		key := effect.Op + "\x00" + effect.Proto + "\x00" + dst
		group := byKey[key]
		if group == nil {
			group = &networkEffectGroup{Op: emptyAs(effect.Op, "unknown"), Proto: emptyAs(effect.Proto, "unknown"), Destination: dst}
			byKey[key] = group
		}
		group.Count++
		group.Bytes += effect.Bytes
		group.Detection = group.Detection || detected[effect.Seq]
	}
	groups := make([]*networkEffectGroup, 0, len(byKey))
	for _, group := range byKey {
		groups = append(groups, group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Detection != groups[j].Detection {
			return groups[i].Detection
		}
		return groups[i].Destination < groups[j].Destination
	})
	shown := len(groups)
	if shown > limit {
		shown = limit
	}
	for _, group := range groups[:shown] {
		marker, count := " ", ""
		if group.Detection {
			marker = "⚠"
		}
		if group.Count > 1 {
			count = fmt.Sprintf(" (x%d)", group.Count)
		}
		_, _ = fmt.Fprintf(w, "  %s %-8s %-7s %s%s bytes=%d\n", marker, group.Op, group.Proto, group.Destination, count, group.Bytes)
	}
	if shown < len(groups) {
		_, _ = fmt.Fprintf(w, "  ... %d destination group(s) omitted; use --verbose\n", len(groups)-shown)
	}
}

func networkDestination(effect residual.NetworkEffect) string {
	if effect.DstPort > 0 {
		return net.JoinHostPort(effect.DstIP, strconv.Itoa(int(effect.DstPort)))
	}
	return emptyAs(effect.DstIP, "unknown")
}

func detectionSeqSet(detections []actionview.Detection) map[int64]bool {
	out := make(map[int64]bool, len(detections))
	for _, detection := range detections {
		out[detection.RelatedEventSeq] = true
	}
	return out
}

func inspectUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	_, _ = fmt.Fprintf(w, "%s inspect: inspect one agent-reported command and its observed episode\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s inspect [last|<run-id>] action:<ordinal-or-item-id> [flags]\n\n", prog)
	_, _ = fmt.Fprintln(w, "Examples:")
	_, _ = fmt.Fprintf(w, "  %s inspect last action:3\n", prog)
	_, _ = fmt.Fprintf(w, "  %s inspect last action:item_123 --verbose\n", prog)
	_, _ = fmt.Fprintf(w, "  %s inspect last action:3 --json\n\n", prog)
	_, _ = fmt.Fprintln(w, "Notes:")
	_, _ = fmt.Fprintln(w, "  Ordinals are run-local display indexes; item IDs are stable within stored runtime telemetry.")
	_, _ = fmt.Fprintln(w, "  Detections are attributed only through exact related_event_seq episode membership.")
	_, _ = fmt.Fprintln(w, "  Inspection reports observation and correlation, not semantic expectedness or intent.")
	_, _ = fmt.Fprintln(w, "\nFlags:")
	fs.PrintDefaults()
}
