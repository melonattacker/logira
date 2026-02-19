package cli

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/cliui"
	"github.com/melonattacker/logira/internal/storage"
)

type groupedDetection struct {
	Severity         string
	RuleID           string
	Message          string
	Count            int
	FirstTS          int64
	LastTS           int64
	SampleRelatedSeq int64
}

func severityWeight(v string) int {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

func groupDetectionsFromEvents(evs []storage.Event, limit int) []groupedDetection {
	type key struct {
		sev string
		rid string
		msg string
	}
	m := map[key]*groupedDetection{}
	for _, ev := range evs {
		if ev.Type != storage.TypeDetection {
			continue
		}
		var d storage.Detection
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		k := key{sev: d.Severity, rid: d.RuleID, msg: d.Message}
		cur := m[k]
		if cur == nil {
			cur = &groupedDetection{
				Severity: d.Severity,
				RuleID:   d.RuleID,
				Message:  d.Message,
				Count:    0,
				FirstTS:  ev.TS,
				LastTS:   ev.TS,
			}
			m[k] = cur
		}
		cur.Count++
		if ev.TS < cur.FirstTS {
			cur.FirstTS = ev.TS
		}
		if ev.TS > cur.LastTS {
			cur.LastTS = ev.TS
		}
		if cur.SampleRelatedSeq == 0 && d.RelatedEventSeq > 0 {
			cur.SampleRelatedSeq = d.RelatedEventSeq
		}
	}
	out := make([]groupedDetection, 0, len(m))
	for _, g := range m {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		wi := severityWeight(out[i].Severity)
		wj := severityWeight(out[j].Severity)
		if wi == wj {
			if out[i].Count == out[j].Count {
				return out[i].RuleID < out[j].RuleID
			}
			return out[i].Count > out[j].Count
		}
		return wi > wj
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func evidenceFromEvent(ev storage.Event, max int) string {
	switch ev.Type {
	case storage.TypeNet:
		d, err := parseNetDetail(ev.DataJSON)
		if err != nil {
			return cliui.Truncate(ev.Summary, max)
		}
		dst := strings.TrimSpace(d.DstIP)
		if d.DstPort > 0 {
			dst = fmt.Sprintf("%s:%d", dst, d.DstPort)
		}
		base := strings.TrimSpace(d.Op)
		if base == "" {
			base = "net"
		}
		if dst != "" {
			base += " " + dst
		}
		if d.Bytes > 0 {
			base += fmt.Sprintf(" bytes=%d", d.Bytes)
		}
		return cliui.Truncate(base, max)
	case storage.TypeFile:
		d, err := parseFileDetail(ev.DataJSON)
		if err != nil {
			return cliui.Truncate(ev.Summary, max)
		}
		p := strings.TrimSpace(d.Path)
		if p == "" {
			p = "-"
		}
		op := strings.TrimSpace(d.Op)
		if op == "" {
			op = "file"
		}
		return cliui.Truncate(op+" "+p, max)
	case storage.TypeExec:
		d, err := parseExecDetail(ev.DataJSON)
		if err != nil {
			return cliui.Truncate(ev.Summary, max)
		}
		base := strings.TrimSpace(d.Filename)
		if base == "" && len(d.Argv) > 0 {
			base = d.Argv[0]
		}
		if len(d.Argv) > 1 {
			base += " " + strings.Join(d.Argv[1:], " ")
		}
		if base == "" {
			base = ev.Summary
		}
		return cliui.Truncate("exec "+base, max)
	default:
		return cliui.Truncate(ev.Summary, max)
	}
}

func countDetectionsBySeverityFromEvents(evs []storage.Event) map[string]int {
	out := map[string]int{}
	for _, ev := range evs {
		if ev.Type != storage.TypeDetection {
			continue
		}
		var d storage.Detection
		if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
			continue
		}
		out[d.Severity]++
	}
	return out
}
