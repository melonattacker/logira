//go:build linux

package ipc

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/melonattacker/logira/internal/model"
)

// JSONL protocol: 1 message per line.
// Every message must have a "type" field.

const (
	MsgTypeStartRun             = "start_run"
	MsgTypeStartRunOK           = "start_run_ok"
	MsgTypeStopRun              = "stop_run"
	MsgTypeAttachPID            = "attach_pid"
	MsgTypeStatus               = "status"
	MsgTypeStatusOK             = "status_ok"
	MsgTypeAppendAgentEvent     = "append_agent_event"
	MsgTypeFinishAgentTelemetry = "finish_agent_telemetry"
	MsgTypeOK                   = "ok"
	MsgTypeError                = "error"
)

type Envelope struct {
	Type string `json:"type"`
}

type StartRunRequest struct {
	Type string `json:"type"`

	RunID      string   `json:"run_id"`
	Tool       string   `json:"tool"`
	CmdArgv    []string `json:"cmd_argv"`
	CWD        string   `json:"cwd"`
	LogiraHome string   `json:"logira_home,omitempty"`

	EnableExec bool `json:"enable_exec"`
	EnableFile bool `json:"enable_file"`
	EnableNet  bool `json:"enable_net"`

	WatchPaths   []string `json:"watch_paths,omitempty"`
	ArgvMax      int      `json:"argv_max,omitempty"`
	ArgvMaxBytes int      `json:"argv_max_bytes,omitempty"`
	HashMaxBytes int64    `json:"hash_max_bytes,omitempty"`

	CustomRulesPath string `json:"custom_rules_path,omitempty"`
	CustomRulesYAML []byte `json:"custom_rules_yaml,omitempty"`
	AgentProvider   string `json:"agent_provider,omitempty"`
}

type AppendAgentEventRequest struct {
	Type      string            `json:"type"`
	SessionID string            `json:"session_id"`
	Detail    model.AgentDetail `json:"detail"`
}

type AgentTelemetryStats struct {
	Capture        string `json:"capture"`
	Interpretation string `json:"interpretation"`
	LinesSeen      uint64 `json:"lines_seen"`
	LinesPersisted uint64 `json:"lines_persisted"`
	Malformed      uint64 `json:"malformed"`
	UnknownSchema  uint64 `json:"unknown_schema"`
	RawTruncated   uint64 `json:"raw_truncated"`
	AppendFailures uint64 `json:"append_failures"`
}

type FinishAgentTelemetryRequest struct {
	Type      string              `json:"type"`
	SessionID string              `json:"session_id"`
	Stats     AgentTelemetryStats `json:"stats"`
}

type StartRunResponse struct {
	Type string `json:"type"`

	SessionID  string `json:"session_id"`
	CgroupPath string `json:"cgroup_path"`
	RunDir     string `json:"run_dir"`
	CgroupID   uint64 `json:"cgroup_id"`
}

type StopRunRequest struct {
	Type string `json:"type"`

	SessionID string `json:"session_id"`
	ExitCode  int    `json:"exit_code"`
}

// AttachPIDRequest is optional. Clients should prefer writing to cgroup.procs
// directly, but this provides a fallback if delegation fails.
type AttachPIDRequest struct {
	Type string `json:"type"`

	SessionID string `json:"session_id"`
	PID       int    `json:"pid"`
}

type OKResponse struct {
	Type string `json:"type"`
}

type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

type StatusRequest struct {
	Type string `json:"type"`
}

type StatusResponse struct {
	Type string `json:"type"`

	PID int `json:"pid"`
	UID int `json:"uid"`
	GID int `json:"gid"`

	EnableExec bool `json:"enable_exec"`
	EnableFile bool `json:"enable_file"`
	EnableNet  bool `json:"enable_net"`
}

func DecodeType(line []byte) (string, error) {
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return "", err
	}
	return strings.TrimSpace(env.Type), nil
}

func MustLine(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func NewErrorf(format string, args ...any) ErrorResponse {
	return ErrorResponse{Type: MsgTypeError, Message: fmt.Sprintf(format, args...)}
}
