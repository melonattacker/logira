package model

type ExecDetail struct {
	Filename     string   `json:"filename"`
	Argv         []string `json:"argv,omitempty"`
	Comm         string   `json:"comm,omitempty"`
	CWD          string   `json:"cwd,omitempty"`
	KernelTimeNS uint64   `json:"kernel_time_ns,omitempty"`
	CgroupID     uint64   `json:"cgroup_id,omitempty"`
}

type FileDetail struct {
	Op            string `json:"op"`
	Path          string `json:"path"`
	PID           int    `json:"pid,omitempty"`
	PPID          int    `json:"ppid,omitempty"`
	UID           int    `json:"uid,omitempty"`
	SizeBefore    *int64 `json:"size_before,omitempty"`
	SizeAfter     *int64 `json:"size_after,omitempty"`
	HashBefore    string `json:"hash_before,omitempty"`
	HashAfter     string `json:"hash_after,omitempty"`
	HashTruncated bool   `json:"hash_truncated,omitempty"`
	CgroupID      uint64 `json:"cgroup_id,omitempty"`
}

type NetDetail struct {
	Op       string `json:"op"`
	Proto    string `json:"proto"`
	DstIP    string `json:"dst_ip,omitempty"`
	DstPort  uint16 `json:"dst_port,omitempty"`
	Bytes    int64  `json:"bytes,omitempty"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
}
