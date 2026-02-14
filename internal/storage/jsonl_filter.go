package storage

import (
	"encoding/json"
	"strings"

	"github.com/melonattacker/agentlogix/internal/model"
)

func Filter(events []Event, opts QueryOptions) []Event {
	contains := strings.ToLower(strings.TrimSpace(opts.Contains))
	path := strings.TrimSpace(opts.Path)
	dstIP := strings.TrimSpace(opts.DstIP)
	sev := strings.TrimSpace(opts.Severity)

	out := make([]Event, 0, len(events))
	for _, ev := range events {
		if opts.RunID != "" && ev.RunID != opts.RunID {
			continue
		}
		if opts.SinceTS > 0 && ev.TS < opts.SinceTS {
			continue
		}
		if opts.Type != "" && ev.Type != opts.Type {
			continue
		}
		if contains != "" {
			s := strings.ToLower(ev.Summary + " " + string(ev.DataJSON))
			if !strings.Contains(s, contains) {
				continue
			}
		}
		if path != "" && ev.Type == TypeFile {
			var d model.FileDetail
			if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
				continue
			}
			if !strings.Contains(d.Path, path) {
				continue
			}
		}
		if dstIP != "" && ev.Type == TypeNet {
			var d model.NetDetail
			if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
				continue
			}
			if d.DstIP != dstIP {
				continue
			}
		}
		if opts.DstPort > 0 && ev.Type == TypeNet {
			var d model.NetDetail
			if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
				continue
			}
			if int(d.DstPort) != opts.DstPort {
				continue
			}
		}
		if sev != "" && ev.Type == TypeDetection {
			var d Detection
			if err := json.Unmarshal(ev.DataJSON, &d); err != nil {
				continue
			}
			if d.Severity != sev {
				continue
			}
		}
		out = append(out, ev)
		if opts.Limit > 0 && len(out) >= opts.Limit {
			break
		}
	}
	return out
}
