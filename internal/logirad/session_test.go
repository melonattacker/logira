//go:build linux

package logirad

import (
	"encoding/json"
	"testing"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
)

func TestNormalizeFileDetail_DoesNotFilterByWatchPaths(t *testing.T) {
	s := &session{
		meta: runs.Meta{
			CWD:        "/tmp",
			WatchPaths: []string{"."},
		},
	}

	b, err := json.Marshal(model.FileDetail{
		Op:   "open",
		Path: "/home/u/.netrc",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	d, ok := s.normalizeFileDetail(collector.Event{
		PID:    1234,
		PPID:   1,
		UID:    1000,
		Detail: b,
	})
	if !ok {
		t.Fatalf("expected file detail to be accepted regardless of watch_paths")
	}
	if d.Path != "/home/u/.netrc" {
		t.Fatalf("path mismatch: got %q", d.Path)
	}
}
