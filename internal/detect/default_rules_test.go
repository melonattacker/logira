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

func TestLoadRulesYAML_FilePathRegex(t *testing.T) {
	yaml := []byte(`
rules:
  - id: "F901"
    title: "Regex file rule"
    type: "file"
    severity: "low"
    when:
      file:
        path_regex: "^/tmp/.+/.env(\\..+)?$"
        op_in: ["open"]
    message: "regex rule"
`)
	rs, err := LoadRulesYAML(yaml)
	if err != nil {
		t.Fatalf("LoadRulesYAML: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs))
	}
	if rs[0].When.File == nil || rs[0].When.File.pathRegexRE == nil {
		t.Fatalf("expected compiled file path regex")
	}
}

func TestCompilePathRegex_HomeExpansion(t *testing.T) {
	re, err := compilePathRegex("^$HOME/\\.ssh/id_ed25519$", "/home/u")
	if err != nil {
		t.Fatalf("compilePathRegex: %v", err)
	}
	if !re.MatchString("/home/u/.ssh/id_ed25519") {
		t.Fatalf("expected expanded home regex to match")
	}
	if re.MatchString("$HOME/.ssh/id_ed25519") {
		t.Fatalf("did not expect literal $HOME to match when home is known")
	}
}

func TestLoadRulesYAML_FileRuleRequiresSelector(t *testing.T) {
	yaml := []byte(`
rules:
  - id: "F999"
    title: "Invalid file rule"
    type: "file"
    severity: "low"
    when:
      file:
        op_in: ["open"]
    message: "invalid"
`)
	if _, err := LoadRulesYAML(yaml); err == nil {
		t.Fatalf("expected validation error for file rule without selector")
	}
}
