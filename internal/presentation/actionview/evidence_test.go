package actionview

import (
	"fmt"
	"testing"

	"github.com/melonattacker/logira/internal/analyzer/residual"
)

func TestBuildExecutionTreesKeepsFullEvidenceAndProtectsSignificantNodes(t *testing.T) {
	members := []residual.ExecMember{
		{Seq: 1, Filename: "/home/u/.codex/tmp/codex-linux-sandbox", Argv: []string{"codex-linux-sandbox"}, Role: residual.ExecRoleWrapper},
		{Seq: 2, ParentExecSeq: 1, Filename: "/usr/bin/bwrap", Role: residual.ExecRoleWrapper},
		{Seq: 3, ParentExecSeq: 2, Filename: "/bin/bash", Argv: []string{"bash", "-c", "go test ./..."}, Role: residual.ExecRoleDirectMatch},
		{Seq: 4, ParentExecSeq: 3, Filename: "/usr/bin/go", Role: residual.ExecRoleExecReplacement},
	}
	for i := 0; i < 3; i++ {
		members = append(members, residual.ExecMember{Seq: int64(5 + i), ParentExecSeq: 4, Filename: "/usr/lib/go/pkg/tool/compile", Role: residual.ExecRoleDescendant})
	}
	for i := 0; i < 15; i++ {
		members = append(members, residual.ExecMember{Seq: int64(8 + i), ParentExecSeq: 4, Filename: fmt.Sprintf("/tmp/tool-%d", i), Role: residual.ExecRoleDescendant})
	}
	detectedSeq := int64(23)
	members = append(members, residual.ExecMember{Seq: detectedSeq, ParentExecSeq: 4, Filename: "/usr/lib/go/pkg/tool/compile", Role: residual.ExecRoleDescendant})
	trees := BuildExecutionTrees("/repo", "codex", residual.ExecutionEpisode{AncestryComplete: true, ExecMembers: members}, []Detection{{RelatedEventSeq: detectedSeq}})
	if trees.CollapsedInfrastructure != 2 || trees.GroupedLeafObservations != 3 || !trees.Large {
		t.Fatalf("unexpected compression: %+v", trees)
	}
	if countExecutionNodes(trees.FullRoots) != len(members) {
		t.Fatalf("full tree lost evidence: got %d want %d", countExecutionNodes(trees.FullRoots), len(members))
	}
	if !treeContainsDetected(trees.DefaultRoots, detectedSeq) {
		t.Fatal("detected leaf was grouped or omitted")
	}
}

func TestEffectGroupingNormalizesAndPreservesProvenance(t *testing.T) {
	files := GroupFileEffects("/repo", []residual.FileEffect{
		{Seq: 1, Op: "modify", Path: "/repo/result", Attribution: "task_instance_latest_exec_generation"},
		{Seq: 2, Op: "truncate", Path: "/repo/result", Attribution: "task_instance_no_exec"},
	}, []Detection{{RelatedEventSeq: 2}})
	if len(files) != 1 || files[0].Op != "MODIFY" || files[0].Path != "result" || files[0].Count != 2 || !files[0].Detection || !files[0].AttributionIncomplete {
		t.Fatalf("unexpected file grouping: %+v", files)
	}
	networks := GroupNetworkEffects([]residual.NetworkEffect{
		{Seq: 3, Op: "send", Proto: "tcp", DstIP: "192.0.2.1", DstPort: 443, Bytes: 10},
		{Seq: 4, Op: "send", Proto: "tcp", DstIP: "192.0.2.1", DstPort: 443, Bytes: 20},
	}, nil)
	if len(networks) != 1 || networks[0].Count != 2 || networks[0].Bytes != 30 || networks[0].Destination != "192.0.2.1:443" {
		t.Fatalf("unexpected network grouping: %+v", networks)
	}
}

func countExecutionNodes(nodes []*ExecutionTreeNode) int {
	total := 0
	for _, node := range nodes {
		total++
		total += countExecutionNodes(node.Children)
	}
	return total
}

func treeContainsDetected(nodes []*ExecutionTreeNode, seq int64) bool {
	for _, node := range nodes {
		if node.Member.Seq == seq && node.Detected && node.GroupCount == 0 {
			return true
		}
		if treeContainsDetected(node.Children, seq) {
			return true
		}
	}
	return false
}
