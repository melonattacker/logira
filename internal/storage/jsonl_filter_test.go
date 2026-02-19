package storage

import (
	"encoding/json"
	"testing"
)

func TestFilter_Basic(t *testing.T) {
	evs := []Event{
		{
			RunID:   "r1",
			Seq:     1,
			TS:      10,
			Type:    TypeFile,
			Summary: "file modify /home/u/.ssh/config",
			DataJSON: mustJSON(t, map[string]any{
				"op":   "modify",
				"path": "/home/u/.ssh/config",
			}),
		},
		{
			RunID:   "r1",
			Seq:     2,
			TS:      11,
			Type:    TypeNet,
			Summary: "net connect 1.2.3.4:443 bytes=0",
			DataJSON: mustJSON(t, map[string]any{
				"op":       "connect",
				"dst_ip":   "1.2.3.4",
				"dst_port": 443,
			}),
		},
		{
			RunID:   "r1",
			Seq:     3,
			TS:      12,
			Type:    TypeDetection,
			Summary: "[high] R4: curl|sh pattern",
			DataJSON: mustJSON(t, Detection{
				RuleID:          "R4",
				Severity:        "high",
				Message:         "curl piped to shell",
				RelatedEventSeq: 2,
			}),
		},
		{
			RunID:   "r2",
			Seq:     1,
			TS:      10,
			Type:    TypeDetection,
			Summary: "[low] R1: something else",
			DataJSON: mustJSON(t, Detection{
				RuleID:   "R1",
				Severity: "low",
				Message:  "other",
			}),
		},
	}

	out := Filter(evs, QueryOptions{RunID: "r1", Type: TypeFile, Path: ".ssh"})
	if len(out) != 1 || out[0].Seq != 1 {
		t.Fatalf("expected seq=1, got %#v", out)
	}

	out = Filter(evs, QueryOptions{RunID: "r1", Type: TypeNet, DstIP: "1.2.3.4", DstPort: 443})
	if len(out) != 1 || out[0].Seq != 2 {
		t.Fatalf("expected seq=2, got %#v", out)
	}

	out = Filter(evs, QueryOptions{RunID: "r1", Type: TypeDetection, Severity: "high"})
	if len(out) != 1 || out[0].Seq != 3 {
		t.Fatalf("expected seq=3, got %#v", out)
	}

	out = Filter(evs, QueryOptions{RunID: "r1", Contains: "curl piped"})
	if len(out) != 1 || out[0].Seq != 3 {
		t.Fatalf("expected contains to match detection seq=3, got %#v", out)
	}

	out = Filter(evs, QueryOptions{RunID: "r1", RelatedToDetections: true})
	if len(out) != 1 || out[0].Seq != 2 {
		t.Fatalf("expected related event seq=2, got %#v", out)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return json.RawMessage(b)
}
