package model

import "encoding/json"

type ExecDetail struct {
	Filename              string   `json:"filename"`
	Argv                  []string `json:"argv,omitempty"`
	Comm                  string   `json:"comm,omitempty"`
	CWD                   string   `json:"cwd,omitempty"`
	KernelTimeNS          uint64   `json:"kernel_time_ns,omitempty"`
	TID                   int      `json:"tid,omitempty"`
	TGID                  int      `json:"tgid,omitempty"`
	OldPID                int      `json:"old_pid,omitempty"`
	TaskStartKernelNS     uint64   `json:"task_start_kernel_ns,omitempty"`
	FirstObservedKernelNS uint64   `json:"first_observed_kernel_ns,omitempty"`
	CgroupID              uint64   `json:"cgroup_id,omitempty"`
}

// ProcessDetail records kernel-observed task lifecycle. TaskStartKernelNS is
// bpf_ktime_get_ns() at sched_process_fork, not a task_struct start field.
type ProcessDetail struct {
	Kind                    string `json:"kind"`
	TID                     int    `json:"tid"`
	TGID                    int    `json:"tgid,omitempty"`
	ParentTID               int    `json:"parent_tid,omitempty"`
	ParentTGID              int    `json:"parent_tgid,omitempty"`
	ParentTaskStartKernelNS uint64 `json:"parent_task_start_kernel_ns,omitempty"`
	ChildTID                int    `json:"child_tid,omitempty"`
	ChildTGID               int    `json:"child_tgid,omitempty"`
	OldPID                  int    `json:"old_pid,omitempty"`
	TaskStartKernelNS       uint64 `json:"task_start_kernel_ns,omitempty"`
	FirstObservedKernelNS   uint64 `json:"first_observed_kernel_ns,omitempty"`
	KernelTimeNS            uint64 `json:"kernel_time_ns"`
	CloneKind               string `json:"clone_kind,omitempty"`
	GroupDead               string `json:"group_dead,omitempty"`
	CgroupID                uint64 `json:"cgroup_id,omitempty"`
}

type FileDetail struct {
	Op                string `json:"op"`
	Syscall           string `json:"syscall,omitempty"`
	Correlation       string `json:"correlation,omitempty"`
	Path              string `json:"path"`
	Path2             string `json:"path2,omitempty"`
	RawPath           string `json:"raw_path,omitempty"`
	RawPath2          string `json:"raw_path2,omitempty"`
	PathResolution    string `json:"path_resolution,omitempty"`
	PathResolution2   string `json:"path_resolution2,omitempty"`
	FD                *int   `json:"fd,omitempty"`
	DirFD             *int   `json:"dirfd,omitempty"`
	DirFD2            *int   `json:"dirfd2,omitempty"`
	Flags             uint32 `json:"flags,omitempty"`
	ReturnValue       int64  `json:"return_value,omitempty"`
	Bytes             int64  `json:"bytes,omitempty"`
	PID               int    `json:"pid,omitempty"`
	TID               int    `json:"tid,omitempty"`
	TGID              int    `json:"tgid,omitempty"`
	TaskStartKernelNS uint64 `json:"task_start_kernel_ns,omitempty"`
	KernelTimeNS      uint64 `json:"kernel_time_ns,omitempty"`
	PPID              int    `json:"ppid,omitempty"`
	UID               int    `json:"uid,omitempty"`
	SizeBefore        *int64 `json:"size_before,omitempty"`
	SizeAfter         *int64 `json:"size_after,omitempty"`
	HashBefore        string `json:"hash_before,omitempty"`
	HashAfter         string `json:"hash_after,omitempty"`
	HashTruncated     bool   `json:"hash_truncated,omitempty"`
	CgroupID          uint64 `json:"cgroup_id,omitempty"`
}

type NetDetail struct {
	Op                string `json:"op"`
	Proto             string `json:"proto"`
	DstIP             string `json:"dst_ip,omitempty"`
	DstPort           uint16 `json:"dst_port,omitempty"`
	Bytes             int64  `json:"bytes,omitempty"`
	CgroupID          uint64 `json:"cgroup_id,omitempty"`
	TID               int    `json:"tid,omitempty"`
	TGID              int    `json:"tgid,omitempty"`
	TaskStartKernelNS uint64 `json:"task_start_kernel_ns,omitempty"`
	KernelTimeNS      uint64 `json:"kernel_time_ns,omitempty"`
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
