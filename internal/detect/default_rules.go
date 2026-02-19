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

const (
	DefaultRulesProfile  = "default"
	SecurityRulesProfile = "security"
	StrictRulesProfile   = "strict"
)

var supportedProfiles = []string{
	DefaultRulesProfile,
	SecurityRulesProfile,
	StrictRulesProfile,
}

var builtinRuleFiles = map[string]string{
	DefaultRulesProfile:  "rules/default_rules.yaml",
	SecurityRulesProfile: "rules/security_rules.yaml",
}

//go:embed rules/*.yaml
var rulesFS embed.FS

type ruleFile struct {
	Rules []Rule `yaml:"rules"`
}

func LoadDefaultRules() ([]Rule, error) {
	return LoadProfileRules(DefaultRulesProfile)
}

func NormalizeRulesProfile(profile string) string {
	p := strings.ToLower(strings.TrimSpace(profile))
	if p == "" {
		return DefaultRulesProfile
	}
	return p
}

func LoadProfileRules(profile string) ([]Rule, error) {
	profile = NormalizeRulesProfile(profile)

	switch profile {
	case DefaultRulesProfile, SecurityRulesProfile:
		return loadBuiltinProfile(profile)
	case StrictRulesProfile:
		// strict is a profile union, so defaults remain centralized.
		out := make([]Rule, 0, 128)
		seen := map[string]struct{}{}
		for _, name := range []string{DefaultRulesProfile, SecurityRulesProfile} {
			rs, err := loadBuiltinProfile(name)
			if err != nil {
				return nil, err
			}
			for _, r := range rs {
				if _, ok := seen[r.ID]; ok {
					continue
				}
				seen[r.ID] = struct{}{}
				out = append(out, r)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unknown rules profile %q (supported: %s)", profile, strings.Join(supportedProfiles, ", "))
	}
}

func loadBuiltinProfile(profile string) ([]Rule, error) {
	path, ok := builtinRuleFiles[profile]
	if !ok {
		return nil, fmt.Errorf("unknown builtin rules profile %q", profile)
	}
	b, err := rulesFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules profile %q (%s): %w", profile, path, err)
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

func SupportedProfiles() []string {
	out := make([]string, len(supportedProfiles))
	copy(out, supportedProfiles)
	return out
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
		if err := validateFileWhen(*r.When.File); err != nil {
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

func validateFileWhen(w FileWhen) error {
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
	if set > 1 {
		return fmt.Errorf("file.when: only one of prefix/prefix_any/path_in may be set")
	}
	return nil
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
