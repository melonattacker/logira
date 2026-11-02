//go:build linux

package linuxcollector

import (
	"encoding/json"
	"github.com/melonattacker/logira/internal/model"
	"os"
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

func TestExecEnrichmentPreservesIntegerIdentity(t *testing.T) {
	detail := model.ExecDetail{Filename: "/bin/test", TaskStartKernelNS: 1<<60 + 1, CgroupID: 1<<60 + 3}
	raw, _ := json.Marshal(detail)
	c := NewCollector(collector.Config{})
	ev := c.enrichExecCWD(collector.Event{Type: collector.EventTypeExec, PID: os.Getpid(), Detail: raw})
	var got model.ExecDetail
	if err := json.Unmarshal(ev.Detail, &got); err != nil {
		t.Fatal(err)
	}
	if got.TaskStartKernelNS != detail.TaskStartKernelNS || got.CgroupID != detail.CgroupID {
		t.Fatalf("identity rounded: %+v", got)
	}
}
