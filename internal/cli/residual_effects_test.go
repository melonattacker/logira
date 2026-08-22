package cli

import (
	"testing"

	"github.com/melonattacker/logira/internal/analyzer/residual"
)

func TestCompactEpisodeExecGroupsGroupsAndBoundsOutput(t *testing.T) {
	episode := residual.ExecutionEpisode{ExecMembers: []residual.ExecMember{
		{Role: residual.ExecRoleDirectMatch, Summary: "exec make test"},
		{Role: residual.ExecRoleDescendant, Summary: "exec compile -V"},
		{Role: residual.ExecRoleDescendant, Summary: "exec compile -V"},
		{Role: residual.ExecRoleDescendant, Summary: "exec link"},
		{Role: residual.ExecRoleExecReplacement, Summary: "exec test binary"},
	}}
	groups, omitted := compactEpisodeExecGroups(episode, 2)
	if len(groups) != 2 || groups[0].Count != 2 || groups[0].Summary != "exec compile -V" {
		t.Fatalf("groups=%+v", groups)
	}
	if omitted != 1 {
		t.Fatalf("omitted=%d, want 1", omitted)
	}
}
