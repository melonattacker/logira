package detect

import (
	"strings"
	"testing"
)

func TestLoadDefaultRules(t *testing.T) {
	rs, err := LoadDefaultRules()
	if err != nil {
		t.Fatalf("LoadDefaultRules: %v", err)
	}
	if len(rs) < 4 {
		t.Fatalf("expected at least 4 rules, got %d", len(rs))
	}
	seen := map[string]bool{}
	for _, r := range rs {
		seen[r.ID] = true
		if r.tmpl == nil {
			t.Fatalf("expected compiled template for %s", r.ID)
		}
	}
	for _, id := range []string{"F001", "F200", "N001", "E001", "E100"} {
		if !seen[id] {
			t.Fatalf("missing rule %s", id)
		}
	}
}

func TestLoadProfileRules_SecurityExcludesAgentSafety(t *testing.T) {
	rs, err := LoadProfileRules(SecurityRulesProfile)
	if err != nil {
		t.Fatalf("LoadProfileRules(security): %v", err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		seen[r.ID] = true
	}
	if seen["E100"] {
		t.Fatalf("security profile must not include E100")
	}
	if !seen["E001"] {
		t.Fatalf("security profile should include existing rules like E001")
	}
}

func TestLoadProfileRules_StrictUnion(t *testing.T) {
	def, err := LoadProfileRules(DefaultRulesProfile)
	if err != nil {
		t.Fatalf("LoadProfileRules(default): %v", err)
	}
	sec, err := LoadProfileRules(SecurityRulesProfile)
	if err != nil {
		t.Fatalf("LoadProfileRules(security): %v", err)
	}
	strict, err := LoadProfileRules(StrictRulesProfile)
	if err != nil {
		t.Fatalf("LoadProfileRules(strict): %v", err)
	}

	defIDs := map[string]struct{}{}
	secIDs := map[string]struct{}{}
	strictIDs := map[string]struct{}{}
	for _, r := range def {
		defIDs[r.ID] = struct{}{}
	}
	for _, r := range sec {
		secIDs[r.ID] = struct{}{}
	}
	for _, r := range strict {
		if _, dup := strictIDs[r.ID]; dup {
			t.Fatalf("strict should not contain duplicate id %q", r.ID)
		}
		strictIDs[r.ID] = struct{}{}
	}

	for id := range defIDs {
		if _, ok := strictIDs[id]; !ok {
			t.Fatalf("strict missing default rule %q", id)
		}
	}
	for id := range secIDs {
		if _, ok := strictIDs[id]; !ok {
			t.Fatalf("strict missing security rule %q", id)
		}
	}
}

func TestLoadProfileRules_Unknown(t *testing.T) {
	_, err := LoadProfileRules("nope")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unknown rules profile") {
		t.Fatalf("unexpected error: %v", err)
	}
}
