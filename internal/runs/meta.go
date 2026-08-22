package runs

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type AgentCoverage struct {
	Capture        string `json:"capture"`
	Interpretation string `json:"interpretation"`
	LinesSeen      uint64 `json:"lines_seen,omitempty"`
	LinesPersisted uint64 `json:"lines_persisted,omitempty"`
	Malformed      uint64 `json:"malformed,omitempty"`
	UnknownSchema  uint64 `json:"unknown_schema,omitempty"`
	RawTruncated   uint64 `json:"raw_truncated,omitempty"`
	AppendFailures uint64 `json:"append_failures,omitempty"`
}

type KnownLoss struct {
	CollectorForwardDropped uint64 `json:"collector_forward_dropped,omitempty"`
	SessionQueueDropped     uint64 `json:"session_queue_dropped,omitempty"`
	PersistenceFailures     uint64 `json:"persistence_failures,omitempty"`
	CorrelationFailures     uint64 `json:"correlation_failures,omitempty"`
}

func (l KnownLoss) Total() uint64 {
	return l.CollectorForwardDropped + l.SessionQueueDropped + l.PersistenceFailures + l.CorrelationFailures
}

type KernelCoverage struct {
	Availability string    `json:"availability"`
	Capture      string    `json:"capture"`
	KnownLoss    KnownLoss `json:"known_loss,omitempty"`
}

type DecisionCoverage struct {
	Availability string `json:"availability"`
}

type Coverage struct {
	Agent            AgentCoverage    `json:"agent"`
	Process          KernelCoverage   `json:"process"`
	File             KernelCoverage   `json:"file"`
	Network          KernelCoverage   `json:"network"`
	SandboxDecisions DecisionCoverage `json:"sandbox_decisions"`
}

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
	AgentProvider     string   `json:"agent_provider,omitempty"`
	ExecutionLocation string   `json:"execution_location,omitempty"`
	Coverage          Coverage `json:"coverage"`
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
