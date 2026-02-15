package detect

import (
	"text/template"

	"github.com/melonattacker/logira/internal/storage"
)

type Rule struct {
	ID       string            `yaml:"id"`
	Title    string            `yaml:"title"`
	Type     storage.EventType `yaml:"type"` // exec|file|net
	Severity string            `yaml:"severity"`
	When     WhenClause        `yaml:"when"`
	Message  string            `yaml:"message"`

	tmpl *template.Template `yaml:"-"`
}

type WhenClause struct {
	File *FileWhen `yaml:"file,omitempty"`
	Net  *NetWhen  `yaml:"net,omitempty"`
	Exec *ExecWhen `yaml:"exec,omitempty"`
}

type FileWhen struct {
	Prefix         string   `yaml:"prefix"`
	OpIn           []string `yaml:"op_in"`
	RequireExecBit bool     `yaml:"require_exec_bit"`
}

type NetWhen struct {
	Op         string `yaml:"op"`
	DstPortGte *int   `yaml:"dst_port_gte"`
}

type ExecWhen struct {
	ContainsAll []string `yaml:"contains_all"`
}
