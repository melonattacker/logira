package detect

import (
	"embed"
	"fmt"
	"regexp"
	"strings"
	"text/template"

	"github.com/melonattacker/logira/internal/storage"
	"gopkg.in/yaml.v3"
)

const builtinDefaultRulesFile = "rules/default_rules.yaml"

//go:embed rules/*.yaml
var rulesFS embed.FS

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func LoadDefaultRules() ([]Rule, error) {
	return loadBuiltinDefaultRules()
}

// loadActiveRules is the single boundary for selecting runtime detection rules.
// It currently loads only the built-in default ruleset and exists so future
// custom-rules support can swap sources without touching engine wiring.
func loadActiveRules() ([]Rule, error) {
	return loadBuiltinDefaultRules()
}

func loadBuiltinDefaultRules() ([]Rule, error) {
	b, err := rulesFS.ReadFile(builtinDefaultRulesFile)
	if err != nil {
		return nil, fmt.Errorf("read builtin rules (%s): %w", builtinDefaultRulesFile, err)
	}
	return LoadRulesYAML(b)
}

func LoadRulesYAML(b []byte) ([]Rule, error) {
	var rf ruleFile
	if err := yaml.Unmarshal(b, &rf); err != nil {
		return nil, fmt.Errorf("parse rules yaml: %w", err)
	}
	if len(rf.Rules) == 0 {
		return nil, fmt.Errorf("no rules in yaml")
	}
	out := make([]Rule, 0, len(rf.Rules))
	seen := map[string]struct{}{}
	for _, r := range rf.Rules {
		if err := validateAndCompileRule(&r); err != nil {
			return nil, fmt.Errorf("rule %q: %w", strings.TrimSpace(r.ID), err)
		}
		if _, ok := seen[r.ID]; ok {
			return nil, fmt.Errorf("duplicate rule id %q", r.ID)
		}
		seen[r.ID] = struct{}{}
		out = append(out, r)
	}
	return out, nil
}

func validateAndCompileRule(r *Rule) error {
	r.ID = strings.TrimSpace(r.ID)
	r.Title = strings.TrimSpace(r.Title)
	r.Severity = strings.TrimSpace(r.Severity)
	r.Message = strings.TrimSpace(r.Message)

	if r.ID == "" {
		return fmt.Errorf("missing id")
	}
	if r.Title == "" {
		return fmt.Errorf("missing title")
	}
	switch r.Type {
	case storage.TypeExec, storage.TypeFile, storage.TypeNet:
	default:
		return fmt.Errorf("invalid type %q", r.Type)
	}
	switch r.Severity {
	case "info", "low", "medium", "high":
	default:
		return fmt.Errorf("invalid severity %q", r.Severity)
	}
	if r.Message == "" {
		return fmt.Errorf("missing message")
	}

	switch r.Type {
	case storage.TypeFile:
		if r.When.File == nil {
			return fmt.Errorf("missing when.file")
		}
		if err := validateFileWhen(r.When.File); err != nil {
			return err
		}
	case storage.TypeNet:
		if r.When.Net == nil {
			return fmt.Errorf("missing when.net")
		}
		if err := validateNetWhen(*r.When.Net); err != nil {
			return err
		}
	case storage.TypeExec:
		if r.When.Exec == nil {
			return fmt.Errorf("missing when.exec")
		}
		if err := validateExecWhen(*r.When.Exec); err != nil {
			return err
		}
	}

	// Pre-compile template for runtime efficiency.
	msg := normalizeTemplate(r.Message)
	t, err := template.New(r.ID).Option("missingkey=zero").Parse(msg)
	if err != nil {
		return fmt.Errorf("parse message template: %w", err)
	}
	r.tmpl = t
	return nil
}

var fieldTemplateRe = regexp.MustCompile(`{{\s*(file|net|exec)\.`)

func normalizeTemplate(s string) string {
	// Convert plan.md style `{{file.path}}` to Go template style `{{.file.path}}`.
	// This is intentionally minimal and only targets the expected namespaces.
	return fieldTemplateRe.ReplaceAllString(s, "{{.$1.")
}

func validateFileWhen(w *FileWhen) error {
	if w == nil {
		return fmt.Errorf("missing when.file")
	}
	set := 0
	if strings.TrimSpace(w.Prefix) != "" {
		set++
	}
	if len(w.PrefixAny) > 0 {
		set++
	}
	if len(w.PathIn) > 0 {
		set++
	}
	if strings.TrimSpace(w.PathRegex) != "" {
		set++
	}
	if set > 1 {
		return fmt.Errorf("file.when: only one of prefix/prefix_any/path_in/path_regex may be set")
	}
	if set == 0 {
		return fmt.Errorf("file.when: one of prefix/prefix_any/path_in/path_regex is required")
	}
	if len(w.OpIn) == 0 {
		return fmt.Errorf("file.when: op_in is required")
	}
	for i, rawOp := range w.OpIn {
		op := strings.ToLower(strings.TrimSpace(rawOp))
		if op == "" {
			return fmt.Errorf("file.when: op_in contains empty value")
		}
		if _, ok := allowedFileOps[op]; !ok {
			return fmt.Errorf("file.when: invalid op_in value %q", rawOp)
		}
		w.OpIn[i] = op
	}
	if strings.TrimSpace(w.PathRegex) != "" {
		re, err := compilePathRegex(w.PathRegex, "")
		if err != nil {
			return fmt.Errorf("file.when: invalid path_regex: %w", err)
		}
		w.pathRegexRE = re
	}
	return nil
}

var allowedFileOps = map[string]struct{}{
	"create": {},
	"modify": {},
	"delete": {},
	"open":   {},
	"read":   {},
}

func compilePathRegex(pattern, home string) (*regexp.Regexp, error) {
	s := strings.TrimSpace(pattern)
	if s == "" {
		return nil, nil
	}
	homeReplacement := regexp.QuoteMeta("$HOME")
	if strings.TrimSpace(home) != "" {
		homeReplacement = regexp.QuoteMeta(home)
	}
	s = strings.ReplaceAll(s, "$HOME", homeReplacement)
	return regexp.Compile(s)
}

func validateNetWhen(w NetWhen) error {
	// Nothing mutually exclusive. Keep minimal guardrails.
	for _, p := range w.DstPortIn {
		if p < 0 || p > 65535 {
			return fmt.Errorf("net.when: invalid dst_port_in %d", p)
		}
	}
	return nil
}

func validateExecWhen(w ExecWhen) error {
	// No exclusive rules; allow contains_all and contains_any to coexist.
	return nil
}
