//go:build linux

package linuxcollector

import (
	"encoding/json"
	"testing"

	collector "github.com/melonattacker/logira/collector/common"
)

func TestCollectorForwardLossTracksOnlyRegisteredCgroupsByType(t *testing.T) {
	lc := NewCollector(collector.Config{})
	lc.RegisterLossTarget(42)
	for _, typ := range []string{collector.EventTypeExec, collector.EventTypeProcess, collector.EventTypeFile, collector.EventTypeNet} {
		detail, _ := json.Marshal(map[string]any{"cgroup_id": 42})
		lc.recordForwardDrop(collector.Event{Type: typ, Detail: detail})
	}
	unregistered, _ := json.Marshal(map[string]any{"cgroup_id": 7})
	lc.recordForwardDrop(collector.Event{Type: collector.EventTypeExec, Detail: unregistered})

	got := lc.SnapshotAndUnregisterLossTarget(42)
	if got.Exec != 2 || got.File != 1 || got.Net != 1 {
		t.Fatalf("drops=%+v", got)
	}
	if again := lc.SnapshotAndUnregisterLossTarget(42); again != (collector.DropCounts{}) {
		t.Fatalf("target was not unregistered: %+v", again)
	}
}
