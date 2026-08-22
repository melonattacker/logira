package codex

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/melonattacker/logira/internal/model"
)

const MaxPreservedRaw = 256 * 1024

type ParseResult struct {
	Detail       model.AgentDetail
	KnownSchema  bool
	Malformed    bool
	RawTruncated bool
}

type envelope struct {
	Type     string          `json:"type"`
	ThreadID string          `json:"thread_id"`
	Message  string          `json:"message"`
	Item     json.RawMessage `json:"item"`
}

type item struct {
	ID               string                `json:"id"`
	Type             string                `json:"type"`
	Command          string                `json:"command"`
	Status           string                `json:"status"`
	ExitCode         *int                  `json:"exit_code"`
	Text             string                `json:"text"`
	AggregatedOutput string                `json:"aggregated_output"`
	Items            []model.AgentTodoItem `json:"items"`
}

func ParseLine(line []byte) ParseResult {
	d := model.AgentDetail{Provider: "codex"}
	setRaw(&d, line)
	var env envelope
	if err := json.Unmarshal(line, &env); err != nil {
		d.Kind = "unparsed"
		d.EventType = "malformed"
		d.Raw = nil
		d.RawText = string(line)
		if len(d.RawText) > MaxPreservedRaw {
			d.RawText = d.RawText[:MaxPreservedRaw]
			d.RawTruncated = true
		}
		return ParseResult{Detail: d, Malformed: true, RawTruncated: d.RawTruncated}
	}
	d.EventType = strings.TrimSpace(env.Type)
	d.ThreadID = strings.TrimSpace(env.ThreadID)
	known := true
	switch d.EventType {
	case "thread.started":
		d.Kind = "thread_started"
	case "turn.started":
		d.Kind = "turn_started"
	case "turn.completed":
		d.Kind = "turn_completed"
	case "item.started", "item.completed":
		var it item
		if err := json.Unmarshal(env.Item, &it); err != nil {
			d.Kind = "unknown"
			known = false
			break
		}
		d.ItemID = strings.TrimSpace(it.ID)
		d.Command = it.Command
		d.Status = strings.TrimSpace(it.Status)
		d.ExitCode = it.ExitCode
		d.Text = it.Text
		d.TodoItems = it.Items
		switch it.Type {
		case "command_execution":
			d.Kind = it.Type
			if d.Text == "" {
				d.Text = it.AggregatedOutput
			}
		case "agent_message", "todo_list":
			d.Kind = it.Type
		default:
			d.Kind = "unknown"
			known = false
		}
	default:
		d.Kind = "unknown"
		known = false
	}
	return ParseResult{Detail: d, KnownSchema: known, RawTruncated: d.RawTruncated}
}

func setRaw(d *model.AgentDetail, line []byte) {
	sum := sha256.Sum256(line)
	d.RawSHA256 = hex.EncodeToString(sum[:])
	if len(line) <= MaxPreservedRaw {
		d.Raw = append(json.RawMessage(nil), line...)
		return
	}
	d.RawTruncated = true
	// Keep a valid JSON preview instead of slicing a JSON document into an
	// invalid RawMessage. Correlation fields are parsed from the full line.
	preview, _ := json.Marshal(map[string]any{
		"truncated": true,
		"preview":   string(line[:MaxPreservedRaw]),
	})
	d.Raw = preview
}

func Summary(d model.AgentDetail) string {
	switch d.Kind {
	case "command_execution":
		return strings.TrimSpace("codex command " + d.Command)
	case "agent_message":
		return strings.TrimSpace("codex message " + d.Text)
	case "todo_list":
		return "codex todo list"
	case "thread_started":
		return "codex thread started"
	case "turn_started":
		return "codex turn started"
	case "turn_completed":
		return "codex turn completed"
	default:
		return "codex " + d.Kind
	}
}
