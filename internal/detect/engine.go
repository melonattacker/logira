package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/melonattacker/agentlogix/internal/model"
	"github.com/melonattacker/agentlogix/internal/storage"
)

type Engine struct {
	home string
}

func NewEngine(homeDir string) *Engine {
	return &Engine{home: homeDir}
}

// Evaluate returns zero or more detections for an observed event.
func (e *Engine) Evaluate(typ storage.EventType, data json.RawMessage) []storage.Detection {
	switch typ {
	case storage.TypeFile:
		return e.evalFile(data)
	case storage.TypeNet:
		return e.evalNet(data)
	case storage.TypeExec:
		return e.evalExec(data)
	default:
		return nil
	}
}

func (e *Engine) evalFile(data json.RawMessage) []storage.Detection {
	var d model.FileDetail
	if err := json.Unmarshal(data, &d); err != nil {
		return nil
	}
	path := d.Path
	if path == "" {
		return nil
	}

	out := make([]storage.Detection, 0, 2)

	// R1: write under ~/.ssh
	if strings.HasPrefix(path, filepath.Join(e.home, ".ssh")+string(os.PathSeparator)) && (d.Op == "create" || d.Op == "modify") {
		out = append(out, storage.Detection{
			RuleID:   "R1",
			Severity: "high",
			Message:  fmt.Sprintf("write under %s", filepath.Join(e.home, ".ssh")),
		})
	}

	// R2: executable created under /tmp
	if strings.HasPrefix(path, "/tmp/") && (d.Op == "create" || d.Op == "modify") {
		if fi, err := os.Stat(path); err == nil {
			if fi.Mode()&0o111 != 0 {
				out = append(out, storage.Detection{
					RuleID:   "R2",
					Severity: "medium",
					Message:  "executable file under /tmp",
				})
			}
		}
	}

	return out
}

func (e *Engine) evalNet(data json.RawMessage) []storage.Detection {
	var d model.NetDetail
	if err := json.Unmarshal(data, &d); err != nil {
		return nil
	}
	if d.Op != "connect" {
		return nil
	}
	if d.DstPort >= 1024 {
		return []storage.Detection{{
			RuleID:   "R3",
			Severity: "low",
			Message:  fmt.Sprintf("outbound connect to high port %s:%d", d.DstIP, d.DstPort),
		}}
	}
	return nil
}

func (e *Engine) evalExec(data json.RawMessage) []storage.Detection {
	var d model.ExecDetail
	if err := json.Unmarshal(data, &d); err != nil {
		return nil
	}

	s := strings.ToLower(d.Filename + " " + strings.Join(d.Argv, " "))
	if strings.Contains(s, "curl") && strings.Contains(s, "|") && strings.Contains(s, "sh") {
		return []storage.Detection{{
			RuleID:   "R4",
			Severity: "high",
			Message:  "possible curl|sh execution pattern",
		}}
	}
	return nil
}
