package storage

import "encoding/json"

type EventType string

const (
	TypeExec      EventType = "exec"
	TypeFile      EventType = "file"
	TypeNet       EventType = "net"
	TypeDetection EventType = "detection"
)

type Event struct {
	RunID    string          `json:"run_id"`
	Seq      int64           `json:"seq"`
	TS       int64           `json:"ts"` // unix nanos
	Type     EventType       `json:"type"`
	PID      int             `json:"pid,omitempty"`
	PPID     int             `json:"ppid,omitempty"`
	UID      int             `json:"uid,omitempty"`
	Summary  string          `json:"summary"`
	DataJSON json.RawMessage `json:"data_json"`
}

type Detection struct {
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"` // info|low|medium|high
	Message         string `json:"message"`
	RelatedEventSeq int64  `json:"related_event_seq,omitempty"`
}
