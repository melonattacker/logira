package detect

import "testing"

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

func TestLoadActiveRules(t *testing.T) {
	rs, err := loadActiveRules()
	if err != nil {
		t.Fatalf("loadActiveRules: %v", err)
	}
	if len(rs) == 0 {
		t.Fatalf("expected non-empty active rules")
	}
}
