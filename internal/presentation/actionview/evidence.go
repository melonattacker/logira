package actionview

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/melonattacker/logira/internal/analyzer/residual"
)

// ExecutionTreeNode is a presentation-only execution tree node. GroupCount is
// greater than zero only for a compressed set of equivalent sibling leaves.
type ExecutionTreeNode struct {
	Member     residual.ExecMember
	Detected   bool
	GroupCount int
	Children   []*ExecutionTreeNode
}

// ExecutionTrees contains both the normal compressed forest and the original
// uncompressed forest. Neither changes the stored ExecutionEpisode.
type ExecutionTrees struct {
	DefaultRoots            []*ExecutionTreeNode
	FullRoots               []*ExecutionTreeNode
	CollapsedInfrastructure int
	GroupedLeafObservations int
	TotalExecObservations   int
	Large                   bool
	AncestryComplete        bool
}

type executionNode struct {
	member   residual.ExecMember
	parent   *executionNode
	children []*executionNode
	hidden   bool
	infra    string
}

// BuildExecutionTrees applies the same structural compression used by action
// inspection while retaining a full forest for evidence-on-demand renderers.
func BuildExecutionTrees(workspaceRoot, provider string, episode residual.ExecutionEpisode, detections []Detection) ExecutionTrees {
	detected := DetectionSeqSet(detections)
	fullNodes := buildExecutionNodes(episode.ExecMembers)
	fullRoots := executionRoots(fullNodes, false)

	defaultNodes := buildExecutionNodes(episode.ExecMembers)
	collapsed := 0
	if strings.EqualFold(provider, "codex") {
		for _, node := range defaultNodes {
			node.infra = codexInfrastructureKind(node, detected)
			if node.infra != "" {
				node.hidden = true
				collapsed++
			}
		}
	}
	defaultRoots := executionRoots(defaultNodes, true)
	large := len(defaultNodes) > 20
	grouped := 0

	return ExecutionTrees{
		DefaultRoots:            convertExecutionForest(defaultRoots, detected, large, &grouped),
		FullRoots:               convertExecutionForest(fullRoots, detected, false, nil),
		CollapsedInfrastructure: collapsed,
		GroupedLeafObservations: grouped,
		TotalExecObservations:   len(defaultNodes),
		Large:                   large,
		AncestryComplete:        episode.AncestryComplete,
	}
}

func buildExecutionNodes(members []residual.ExecMember) []*executionNode {
	bySeq := make(map[int64]*executionNode, len(members))
	nodes := make([]*executionNode, 0, len(members))
	for _, member := range members {
		node := &executionNode{member: member}
		bySeq[member.Seq] = node
		nodes = append(nodes, node)
	}
	for _, node := range nodes {
		if parent := bySeq[node.member.ParentExecSeq]; parent != nil && node.member.ParentExecSeq > 0 {
			node.parent = parent
			parent.children = append(parent.children, node)
		}
	}
	return nodes
}

func executionRoots(nodes []*executionNode, skipHidden bool) []*executionNode {
	for _, node := range nodes {
		node.children = nil
	}
	roots := make([]*executionNode, 0)
	for _, node := range nodes {
		if skipHidden && node.hidden {
			continue
		}
		parent := node.parent
		if skipHidden {
			for parent != nil && parent.hidden {
				parent = parent.parent
			}
		}
		if parent == nil {
			roots = append(roots, node)
		} else {
			parent.children = append(parent.children, node)
		}
	}
	return roots
}

func convertExecutionForest(roots []*executionNode, detected map[int64]bool, groupLeaves bool, grouped *int) []*ExecutionTreeNode {
	out := make([]*ExecutionTreeNode, 0, len(roots))
	for _, root := range roots {
		out = append(out, convertExecutionNode(root, detected, groupLeaves, grouped))
	}
	return out
}

func convertExecutionNode(node *executionNode, detected map[int64]bool, groupLeaves bool, grouped *int) *ExecutionTreeNode {
	out := &ExecutionTreeNode{Member: node.member, Detected: detected[node.member.Seq]}
	items := executionChildItems(node.children, detected, groupLeaves)
	for _, item := range items {
		child := convertExecutionNode(item.node, detected, groupLeaves, grouped)
		child.GroupCount = item.groupCount
		if item.groupCount > 0 && grouped != nil {
			*grouped += item.groupCount
		}
		out.Children = append(out.Children, child)
	}
	return out
}

type executionChildItem struct {
	node       *executionNode
	groupCount int
}

func executionChildItems(children []*executionNode, detected map[int64]bool, enabled bool) []executionChildItem {
	if !enabled {
		items := make([]executionChildItem, 0, len(children))
		for _, child := range children {
			items = append(items, executionChildItem{node: child})
		}
		return items
	}
	counts := make(map[string]int)
	for _, child := range children {
		if key := executionLeafGroupKey(child, detected); key != "" {
			counts[key]++
		}
	}
	emitted := make(map[string]bool)
	items := make([]executionChildItem, 0, len(children))
	for _, child := range children {
		key := executionLeafGroupKey(child, detected)
		if key == "" || counts[key] < 3 {
			items = append(items, executionChildItem{node: child})
			continue
		}
		if emitted[key] {
			continue
		}
		emitted[key] = true
		items = append(items, executionChildItem{node: child, groupCount: counts[key]})
	}
	return items
}

func executionLeafGroupKey(node *executionNode, detected map[int64]bool) string {
	if node == nil || len(node.children) > 0 || detected[node.member.Seq] || node.member.Role != residual.ExecRoleDescendant {
		return ""
	}
	filename := strings.TrimSpace(node.member.Filename)
	if filename == "" {
		return ""
	}
	return string(node.member.Role) + "\x00" + filepath.Clean(filename)
}

func codexInfrastructureKind(node *executionNode, detected map[int64]bool) string {
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

func hasCodexInfrastructureAncestor(node *executionNode) bool {
	for ; node != nil; node = node.parent {
		if node.infra == "launcher" || node.infra == "bwrap" || node.infra == "wrapper" {
			return true
		}
	}
	return false
}

// ExecDisplayName returns the factual executable display used by CLI and HTML.
func ExecDisplayName(workspaceRoot string, member residual.ExecMember, includeArgs bool) string {
	name := strings.TrimSpace(member.Filename)
	if name != "" {
		filename := filepath.Clean(name)
		name = filepath.Base(filename)
		if qualifier := ExecutableQualifier(workspaceRoot, filename); qualifier != "" {
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

// ExecutableQualifier exposes non-standard and workspace executable identity.
func ExecutableQualifier(workspaceRoot, filename string) string {
	if !filepath.IsAbs(filename) {
		if strings.ContainsRune(filename, os.PathSeparator) {
			return filename
		}
		return ""
	}
	if rel, inside := DisplayWorkspacePath(workspaceRoot, filename); inside {
		return rel
	}
	for _, root := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/lib", "/lib64", "/nix/store", "/snap"} {
		if filename == root || strings.HasPrefix(filename, root+string(os.PathSeparator)) {
			return ""
		}
	}
	return filename
}

// FileEffectGroup is a normalized, presentation-only file effect group.
type FileEffectGroup struct {
	Op                    string
	Path                  string
	Count                 int
	Detection             bool
	Workspace             bool
	StateChanging         bool
	AttributionIncomplete bool
	InspectPriority       int
}

// GroupFileEffects groups exact normalized operation/path pairs. Its stable
// ordering preserves the existing inspect presentation order.
func GroupFileEffects(workspaceRoot string, effects []residual.FileEffect, detections []Detection) []FileEffectGroup {
	detected := DetectionSeqSet(detections)
	byKey := make(map[string]*FileEffectGroup)
	for _, effect := range effects {
		op := NormalizeFileOp(effect.Op)
		path, workspace := DisplayWorkspacePath(workspaceRoot, effect.Path)
		key := op + "\x00" + path
		group := byKey[key]
		if group == nil {
			group = &FileEffectGroup{Op: op, Path: path, Workspace: workspace, StateChanging: IsStateChangingFileOp(op)}
			byKey[key] = group
		}
		group.Count++
		group.Detection = group.Detection || detected[effect.Seq]
		group.AttributionIncomplete = group.AttributionIncomplete || effect.Attribution != "task_instance_latest_exec_generation"
	}
	groups := make([]FileEffectGroup, 0, len(byKey))
	for _, group := range byKey {
		group.InspectPriority = inspectFileEffectPriority(*group)
		groups = append(groups, *group)
	}
	sort.SliceStable(groups, func(i, j int) bool {
		if groups[i].InspectPriority != groups[j].InspectPriority {
			return groups[i].InspectPriority < groups[j].InspectPriority
		}
		if groups[i].Op != groups[j].Op {
			return groups[i].Op < groups[j].Op
		}
		return groups[i].Path < groups[j].Path
	})
	return groups
}

func NormalizeFileOp(op string) string {
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

func IsStateChangingFileOp(op string) bool {
	switch op {
	case "CREATE", "CREATE/OPEN", "MODIFY", "RENAME", "DELETE":
		return true
	default:
		return false
	}
}

func inspectFileEffectPriority(group FileEffectGroup) int {
	if group.Detection {
		return 0
	}
	if group.Workspace && group.StateChanging {
		return 1
	}
	if group.AttributionIncomplete {
		return 2
	}
	if group.StateChanging {
		return 3
	}
	return 4
}

// DisplayWorkspacePath returns a workspace-relative display path when factual.
func DisplayWorkspacePath(cwd, path string) (string, bool) {
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

// NetworkEffectGroup is a factual operation/protocol/destination aggregate.
type NetworkEffectGroup struct {
	Op          string
	Proto       string
	Destination string
	Count       int
	Bytes       int64
	Detection   bool
}

func GroupNetworkEffects(effects []residual.NetworkEffect, detections []Detection) []NetworkEffectGroup {
	detected := DetectionSeqSet(detections)
	byKey := make(map[string]*NetworkEffectGroup)
	for _, effect := range effects {
		dst := NetworkDestination(effect)
		op := valueOr(effect.Op, "unknown")
		proto := valueOr(effect.Proto, "unknown")
		key := op + "\x00" + proto + "\x00" + dst
		group := byKey[key]
		if group == nil {
			group = &NetworkEffectGroup{Op: op, Proto: proto, Destination: dst}
			byKey[key] = group
		}
		group.Count++
		group.Bytes += effect.Bytes
		group.Detection = group.Detection || detected[effect.Seq]
	}
	groups := make([]NetworkEffectGroup, 0, len(byKey))
	for _, group := range byKey {
		groups = append(groups, *group)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Detection != groups[j].Detection {
			return groups[i].Detection
		}
		if groups[i].Destination != groups[j].Destination {
			return groups[i].Destination < groups[j].Destination
		}
		if groups[i].Op != groups[j].Op {
			return groups[i].Op < groups[j].Op
		}
		return groups[i].Proto < groups[j].Proto
	})
	return groups
}

func NetworkDestination(effect residual.NetworkEffect) string {
	if effect.DstPort > 0 {
		return net.JoinHostPort(effect.DstIP, strconv.Itoa(int(effect.DstPort)))
	}
	return valueOr(effect.DstIP, "unknown")
}

func DetectionSeqSet(detections []Detection) map[int64]bool {
	out := make(map[int64]bool, len(detections))
	for _, detection := range detections {
		out[detection.RelatedEventSeq] = true
	}
	return out
}

func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
