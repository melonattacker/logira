package storage

import "encoding/json"

type EventType string

const (
	TypeExec      EventType = "exec"
	TypeFile      EventType = "file"
	TypeNet       EventType = "net"
	TypeAgent     EventType = "agent"
	TypeDetection EventType = "detection"
)

const (
	ProvenanceRuntimeReported = "agent_runtime_reported"
	ProvenanceKernelObserved  = "kernel_observed"
	ProvenanceDerived         = "logira_derived"
)

type Event struct {
	RunID      string          `json:"run_id"`
	Seq        int64           `json:"seq"`
	TS         int64           `json:"ts"` // unix nanos
	Type       EventType       `json:"type"`
	Provenance string          `json:"provenance"`
	PID        int             `json:"pid,omitempty"`
	PPID       int             `json:"ppid,omitempty"`
	UID        int             `json:"uid,omitempty"`
	Summary    string          `json:"summary"`
	DataJSON   json.RawMessage `json:"data_json"`
}

func ProvenanceForType(typ EventType) string {
	switch typ {
	case TypeAgent:
		return ProvenanceRuntimeReported
	case TypeExec, TypeFile, TypeNet:
		return ProvenanceKernelObserved
	case TypeDetection:
		return ProvenanceDerived
	default:
		return "unknown"
	}
}

type Detection struct {
	RuleID          string `json:"rule_id"`
	Severity        string `json:"severity"` // info|low|medium|high
	Message         string `json:"message"`
	RelatedEventSeq int64  `json:"related_event_seq,omitempty"`
}
