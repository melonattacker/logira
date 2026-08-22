package model

import "encoding/json"

type ExecDetail struct {
	Filename     string   `json:"filename"`
	Argv         []string `json:"argv,omitempty"`
	Comm         string   `json:"comm,omitempty"`
	CWD          string   `json:"cwd,omitempty"`
	KernelTimeNS uint64   `json:"kernel_time_ns,omitempty"`
	CgroupID     uint64   `json:"cgroup_id,omitempty"`
}

type FileDetail struct {
	Op             string `json:"op"`
	Path           string `json:"path"`
	RawPath        string `json:"raw_path,omitempty"`
	PathResolution string `json:"path_resolution,omitempty"`
	FD             *int   `json:"fd,omitempty"`
	DirFD          *int   `json:"dirfd,omitempty"`
	PID            int    `json:"pid,omitempty"`
	PPID           int    `json:"ppid,omitempty"`
	UID            int    `json:"uid,omitempty"`
	SizeBefore     *int64 `json:"size_before,omitempty"`
	SizeAfter      *int64 `json:"size_after,omitempty"`
	HashBefore     string `json:"hash_before,omitempty"`
	HashAfter      string `json:"hash_after,omitempty"`
	HashTruncated  bool   `json:"hash_truncated,omitempty"`
	CgroupID       uint64 `json:"cgroup_id,omitempty"`
}

type NetDetail struct {
	Op       string `json:"op"`
	Proto    string `json:"proto"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
}

type AgentTodoItem struct {
	Text      string `json:"text"`
	Completed bool   `json:"completed"`
}

// AgentDetail is a provider-neutral representation of telemetry reported by
// an agent runtime. It is not model intent and is not independently trusted.
type AgentDetail struct {
	Provider     string          `json:"provider"`
	Kind         string          `json:"kind"`
	EventType    string          `json:"event_type"`
	ThreadID     string          `json:"thread_id,omitempty"`
	ItemID       string          `json:"item_id,omitempty"`
	Command      string          `json:"command,omitempty"`
	Status       string          `json:"status,omitempty"`
	ExitCode     *int            `json:"exit_code,omitempty"`
	Text         string          `json:"text,omitempty"`
	TodoItems    []AgentTodoItem `json:"todo_items,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`
	RawText      string          `json:"raw_text,omitempty"`
	RawTruncated bool            `json:"raw_truncated,omitempty"`
	RawSHA256    string          `json:"raw_sha256,omitempty"`
}
