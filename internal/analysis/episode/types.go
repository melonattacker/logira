// Package episode selects an observed execution lineage. It makes no judgment
// about authorization, intent, expected behavior, or security.
package episode

import (
	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type ProcessMember struct {
	processgraph.Task
	EntrySeq  int64  `json:"entry_seq"`
	EntryKind string `json:"entry_kind"`
}

type Activity struct {
	Event       storage.Event `json:"event"`
	TaskID      *string       `json:"task_id"`
	ExecSeq     *int64        `json:"exec_seq"`
	Generation  *int          `json:"generation"`
	Attribution string        `json:"attribution"`
	Basis       string        `json:"basis"`
	Reason      string        `json:"reason,omitempty"`
}

// Counts partitions all retained observations of one activity type in the run.
// Every event enters exactly one bucket; Unattributable excludes Uncertain.
type Counts struct {
	Observed       int `json:"observed"`
	Attributed     int `json:"attributed"`
	Uncertain      int `json:"uncertain"`
	Unrelated      int `json:"unrelated"`
	Unattributable int `json:"unattributable"`
}

type Summary struct {
	Processes             int            `json:"process_members"`
	Execs                 int            `json:"exec_members"`
	File                  Counts         `json:"file"`
	Network               Counts         `json:"network"`
	UnattributableReasons map[string]int `json:"unattributable_reasons"`
	IgnoredTypes          map[string]int `json:"ignored_event_types"`
}

type Coverage struct {
	Scope         string        `json:"scope"`
	Reported      runs.Coverage `json:"reported"`
	Ancestry      string        `json:"ancestry"`
	ActivityScope string        `json:"activity_scope"`
}

type Source struct {
	Events    string `json:"events"`
	Metadata  string `json:"metadata"`
	MaxSeq    int64  `json:"max_seq"`
	Finalized bool   `json:"finalized"`
}

type Episode struct {
	SchemaVersion   int                  `json:"schema_version"`
	RunID           string               `json:"run_id"`
	RootExecSeq     int64                `json:"root_exec_seq"`
	RootExec        processgraph.Exec    `json:"root_exec"`
	ProcessMembers  []ProcessMember      `json:"process_members"`
	Relationships   []processgraph.Fork  `json:"relationships"`
	ExecMembers     []processgraph.Exec  `json:"exec_members"`
	FileEvents      []Activity           `json:"file_events"`
	NetworkEvents   []Activity           `json:"network_events"`
	UncertainEvents []Activity           `json:"uncertain_events"`
	Summary         Summary              `json:"summary"`
	Coverage        Coverage             `json:"coverage"`
	Limitations     []processgraph.Issue `json:"limitations"`
	AnalysisSource  Source               `json:"analysis_source"`
}
