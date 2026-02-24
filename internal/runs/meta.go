package runs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Meta struct {
	RunID             string   `json:"run_id"`
	StartTS           int64    `json:"start_ts"`
	EndTS             int64    `json:"end_ts,omitempty"`
	Tool              string   `json:"tool"`
	Command           string   `json:"command"`
	CommandArgv       []string `json:"command_argv"`
	CWD               string   `json:"cwd"`
	WatchPaths        []string `json:"watch_paths,omitempty"`
	CustomRules       bool     `json:"custom_rules,omitempty"`
	CustomRulesPath   string   `json:"custom_rules_path,omitempty"`
	CustomRulesSHA256 string   `json:"custom_rules_sha256,omitempty"`
	CgroupPath        string   `json:"cgroup_path,omitempty"`
	SuspiciousCount   int      `json:"suspicious_count"`
	Version           int      `json:"version"`
}

func MetaPath(runDir string) string { return filepath.Join(runDir, "meta.json") }

func WriteMeta(runDir string, m Meta) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(runDir, "meta.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("write meta tmp: %w", err)
	}
	if err := os.Rename(tmp, MetaPath(runDir)); err != nil {
		return fmt.Errorf("rename meta: %w", err)
	}
	return nil
}

func ReadMeta(runDir string) (Meta, error) {
	var m Meta
	b, err := os.ReadFile(MetaPath(runDir))
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, err
	}
	return m, nil
}
