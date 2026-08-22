package codex

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

func TestParseCapturedCodex0147(t *testing.T) {
	f, err := os.Open("testdata/exec-0.147-todo-command.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var kinds []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		r := ParseLine(s.Bytes())
		if !r.KnownSchema || r.Malformed {
			t.Fatalf("unexpected parse result: %+v", r)
		}
		kinds = append(kinds, r.Detail.Kind)
		if r.Detail.Kind == "command_execution" && r.Detail.ItemID != "item_2" {
			t.Fatalf("command item id=%q", r.Detail.ItemID)
		}
		if r.Detail.Kind == "command_execution" && r.Detail.Status == "completed" && r.Detail.Text != "LOGIRA_SCHEMA_MARKER\n" {
			t.Fatalf("command output=%q", r.Detail.Text)
		}
	}
	if err := s.Err(); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(kinds, ",")
	if !strings.Contains(got, "todo_list") || !strings.Contains(got, "command_execution") || !strings.Contains(got, "agent_message") {
		t.Fatalf("kinds=%s", got)
	}
}

func TestUnverifiedFailureAndErrorRemainUnknown(t *testing.T) {
	for _, line := range []string{`{"type":"turn.failed","error":{"message":"no"}}`, `{"type":"error","message":"no"}`} {
		r := ParseLine([]byte(line))
		if r.KnownSchema || r.Detail.Kind != "unknown" || len(r.Detail.Raw) == 0 {
			t.Fatalf("result=%+v", r)
		}
	}
}

func TestParseUnknownAndMalformed(t *testing.T) {
	unknown := ParseLine([]byte(`{"type":"item.completed","item":{"id":"x","type":"future_item"}}`))
	if unknown.KnownSchema || unknown.Malformed || unknown.Detail.Kind != "unknown" || len(unknown.Detail.Raw) == 0 {
		t.Fatalf("unknown=%+v", unknown)
	}
	bad := ParseLine([]byte(`{"type":`))
	if !bad.Malformed || bad.Detail.RawText == "" {
		t.Fatalf("bad=%+v", bad)
	}
}

func TestRawTruncationKeepsParsedFields(t *testing.T) {
	line := `{"type":"item.completed","item":{"id":"x","type":"command_execution","command":"echo hi","status":"completed","exit_code":0,"padding":"` + strings.Repeat("x", MaxPreservedRaw) + `"}}`
	r := ParseLine([]byte(line))
	if !r.KnownSchema || !r.RawTruncated || r.Detail.Command != "echo hi" || r.Detail.RawSHA256 == "" {
		t.Fatalf("result=%+v", r)
	}
}

func TestRawPreservesRecordWhitespace(t *testing.T) {
	line := []byte(`  {"type":"turn.started"}  `)
	r := ParseLine(line)
	if !r.KnownSchema || string(r.Detail.Raw) != string(line) || r.Detail.RawSHA256 == "" {
		t.Fatalf("result=%+v raw=%q", r, r.Detail.Raw)
	}
}
