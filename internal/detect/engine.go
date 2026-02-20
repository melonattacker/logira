package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

type Engine struct {
	home string

	rulesByType map[storage.EventType][]Rule
}

func NewEngine(homeDir string) (*Engine, error) {
	e := &Engine{
		home:        strings.TrimSpace(homeDir),
		rulesByType: map[storage.EventType][]Rule{},
	}
	rules, err := loadActiveRules()
	if err != nil {
		return nil, err
	}
	for _, r := range rules {
		if r.Type == storage.TypeFile && r.When.File != nil && strings.TrimSpace(r.When.File.PathRegex) != "" {
			re, err := compilePathRegex(r.When.File.PathRegex, e.home)
			if err != nil {
				return nil, fmt.Errorf("rule %s: compile path_regex: %w", r.ID, err)
			}
			r.When.File.pathRegexRE = re
		}
		e.rulesByType[r.Type] = append(e.rulesByType[r.Type], r)
	}
	return e, nil
}

// Evaluate returns zero or more detections for an observed event.
func (e *Engine) Evaluate(typ storage.EventType, data json.RawMessage) []storage.Detection {
	rs := e.rulesByType[typ]
	if len(rs) == 0 {
		return nil
	}

	switch typ {
	case storage.TypeFile:
		var d model.FileDetail
		if err := json.Unmarshal(data, &d); err != nil {
			return nil
		}
		return e.evalFileRules(rs, d)
	case storage.TypeNet:
		var d model.NetDetail
		if err := json.Unmarshal(data, &d); err != nil {
			return nil
		}
		return e.evalNetRules(rs, d)
	case storage.TypeExec:
		var d model.ExecDetail
		if err := json.Unmarshal(data, &d); err != nil {
			return nil
		}
		return e.evalExecRules(rs, d)
	default:
		return nil
	}
}

// ShouldRecordFile reports whether a file event matches at least one file rule.
// This is used to keep file event volume bounded using the active ruleset.
func (e *Engine) ShouldRecordFile(d model.FileDetail) bool {
	rs := e.rulesByType[storage.TypeFile]
	if len(rs) == 0 {
		return false
	}
	path := normalizeFilePath(d.Path)
	if path == "" {
		return false
	}
	for _, r := range rs {
		if e.matchFileRule(r, d, path) {
			return true
		}
	}
	return false
}

func (e *Engine) evalFileRules(rs []Rule, d model.FileDetail) []storage.Detection {
	path := normalizeFilePath(d.Path)
	if path == "" {
		return nil
	}

	out := make([]storage.Detection, 0, 2)
	for _, r := range rs {
		if !e.matchFileRule(r, d, path) {
			continue
		}

		msg := e.renderMessage(r, map[string]any{
			"file": map[string]any{
				"path": d.Path,
				"op":   d.Op,
			},
		})
		out = append(out, storage.Detection{
			RuleID:   r.ID,
			Severity: r.Severity,
			Message:  msg,
		})
	}
	return out
}

func normalizeFilePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func (e *Engine) matchFileRule(r Rule, d model.FileDetail, path string) bool {
	w := r.When.File
	if w == nil {
		return false
	}
	if !stringInSlice(strings.ToLower(strings.TrimSpace(d.Op)), w.OpIn) {
		return false
	}
	if !matchFilePath(w, e.home, path) {
		return false
	}
	if w.RequireExecBit {
		fi, err := os.Stat(path)
		if err != nil {
			return false
		}
		if fi.Mode()&0o111 == 0 {
			return false
		}
	}
	return true
}

func (e *Engine) evalNetRules(rs []Rule, d model.NetDetail) []storage.Detection {
	out := make([]storage.Detection, 0, 2)
	for _, r := range rs {
		w := r.When.Net
		if w == nil {
			continue
		}
		if strings.TrimSpace(w.Op) != "" && d.Op != w.Op {
			continue
		}
		if w.DstPortGte != nil && int(d.DstPort) < *w.DstPortGte {
			continue
		}
		if len(w.DstPortIn) > 0 && !intInSlice(int(d.DstPort), w.DstPortIn) {
			continue
		}
		if len(w.DstIPIn) > 0 && !stringInSlice(d.DstIP, w.DstIPIn) {
			continue
		}

		msg := e.renderMessage(r, map[string]any{
			"net": map[string]any{
				"op":       d.Op,
				"proto":    d.Proto,
				"dst_ip":   d.DstIP,
				"dst_port": int(d.DstPort),
				"bytes":    d.Bytes,
			},
		})
		out = append(out, storage.Detection{
			RuleID:   r.ID,
			Severity: r.Severity,
			Message:  msg,
		})
	}
	return out
}

func (e *Engine) evalExecRules(rs []Rule, d model.ExecDetail) []storage.Detection {
	s := strings.ToLower(strings.TrimSpace(d.Filename + " " + strings.Join(d.Argv, " ")))

	out := make([]storage.Detection, 0, 1)
	for _, r := range rs {
		w := r.When.Exec
		if w == nil {
			continue
		}
		if len(w.ContainsAll) > 0 {
			ok := true
			for _, needle := range w.ContainsAll {
				if needle == "" {
					continue
				}
				if !strings.Contains(s, strings.ToLower(needle)) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
		}
		if len(w.ContainsAny) > 0 {
			ok := false
			for _, needle := range w.ContainsAny {
				if needle == "" {
					continue
				}
				if strings.Contains(s, strings.ToLower(needle)) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}

		msg := e.renderMessage(r, map[string]any{
			"exec": map[string]any{
				"filename": d.Filename,
				"argv":     d.Argv,
				"comm":     d.Comm,
				"cwd":      d.CWD,
			},
		})
		out = append(out, storage.Detection{
			RuleID:   r.ID,
			Severity: r.Severity,
			Message:  msg,
		})
	}
	return out
}

func (e *Engine) renderMessage(r Rule, ctx map[string]any) string {
	if r.tmpl == nil {
		return r.Message
	}
	var b bytes.Buffer
	if err := r.tmpl.Execute(&b, ctx); err != nil {
		return r.Message
	}
	return strings.TrimSpace(b.String())
}

func expandHomeVars(s, home string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if home == "" {
		return s
	}
	return strings.ReplaceAll(s, "$HOME", home)
}

func normalizePathPrefix(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	p = filepath.FromSlash(p)
	p = strings.TrimRight(p, string(os.PathSeparator))
	p = filepath.Clean(p)
	// Treat as directory prefix.
	if !strings.HasSuffix(p, string(os.PathSeparator)) {
		p += string(os.PathSeparator)
	}
	return p
}

func stringInSlice(v string, ss []string) bool {
	v = strings.TrimSpace(v)
	for _, s := range ss {
		if strings.TrimSpace(s) == v {
			return true
		}
	}
	return false
}

func intInSlice(v int, xs []int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func matchFilePath(w *FileWhen, home, path string) bool {
	if w == nil {
		return false
	}

	// Exact match list.
	if len(w.PathIn) > 0 {
		for _, p := range w.PathIn {
			p = filepath.Clean(filepath.FromSlash(expandHomeVars(p, home)))
			if strings.TrimSpace(p) == "" {
				continue
			}
			if path == p {
				return true
			}
		}
		return false
	}

	// Any prefix.
	if len(w.PrefixAny) > 0 {
		for _, p := range w.PrefixAny {
			pref := normalizePathPrefix(expandHomeVars(p, home))
			if pref == "" {
				continue
			}
			if strings.HasPrefix(path, pref) {
				return true
			}
		}
		return false
	}

	if w.pathRegexRE != nil {
		return w.pathRegexRE.MatchString(path)
	}

	if strings.TrimSpace(w.PathRegex) != "" {
		re, err := compilePathRegex(w.PathRegex, home)
		if err != nil {
			return false
		}
		return re.MatchString(path)
	}

	// Single prefix (existing behavior).
	if pref := normalizePathPrefix(expandHomeVars(w.Prefix, home)); pref != "" {
		return strings.HasPrefix(path, pref)
	}
	return true
}
