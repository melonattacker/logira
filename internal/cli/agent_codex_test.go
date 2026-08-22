package cli

import "testing"

func TestValidateAgentCommand(t *testing.T) {
	if err := validateAgentCommand("codex", []string{"/usr/bin/codex", "exec", "--json", "hi"}); err != nil {
		t.Fatal(err)
	}
	for _, argv := range [][]string{{"bash", "-lc", "codex exec --json hi"}, {"codex", "exec", "hi"}, {"codex", "--json", "hi"}, {"codex", "other", "exec", "--json"}} {
		if err := validateAgentCommand("codex", argv); err == nil {
			t.Fatalf("expected error for %v", argv)
		}
	}
}
