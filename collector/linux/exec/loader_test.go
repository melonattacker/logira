//go:build linux

package exectrace

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestProcessEventWireLayoutAndKinds(t *testing.T) {
	if got, want := binary.Size(rawProcessEvent{}), 72; got != want {
		t.Fatalf("rawProcessEvent size=%d, want %d", got, want)
	}
	for raw, want := range map[uint32]string{1: "fork", 2: "exit", 3: "exec_rekey", 99: ""} {
		if got := processKind(raw); got != want {
			t.Fatalf("processKind(%d)=%q, want %q", raw, got, want)
		}
	}
}

func TestProcessIdentityRoundTrip(t *testing.T) {
	// Same PID, distinct births; an unknown parent stays unknown. Exec rekeys
	// retain the executing task's identity rather than the replaced leader's.
	fixtures := []rawProcessEvent{
		{Kind: 1, TSNS: 101, CgroupID: 42, TID: 10, TGID: 10, ParentTID: 10, ParentTGID: 10, ChildTID: 20, TaskStartKernelNS: 100},
		{Kind: 2, TSNS: 150, CgroupID: 42, TID: 20, TGID: 20, TaskStartKernelNS: 100},
		{Kind: 1, TSNS: 201, CgroupID: 42, TID: 10, TGID: 10, ParentTID: 10, ParentTGID: 10, ChildTID: 20, TaskStartKernelNS: 200},
		{Kind: 3, TSNS: 220, CgroupID: 42, TID: 30, TGID: 30, OldPID: 20, TaskStartKernelNS: 200},
		{Kind: 2, TSNS: 250, CgroupID: 42, TID: 30, TGID: 30, TaskStartKernelNS: 200},
		{Kind: 2, TSNS: 300, TID: 40, TGID: 40, FirstObservedKernelNS: 300},
	}
	for _, fixture := range fixtures {
		var buf bytes.Buffer
		if err := binary.Write(&buf, binary.NativeEndian, fixture); err != nil {
			t.Fatal(err)
		}
		_, detail, err := decodeProcessEvent(buf.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if detail.TaskStartKernelNS != fixture.TaskStartKernelNS || detail.ParentTaskStartKernelNS != fixture.ParentTaskStartKernelNS || detail.OldPID != int(fixture.OldPID) || detail.FirstObservedKernelNS != fixture.FirstObservedKernelNS {
			t.Fatalf("identity changed: %+v -> %+v", fixture, detail)
		}
		if detail.Kind == "fork" && (detail.ChildTID != 20 || detail.CloneKind != "unknown" || detail.ChildTGID != 0) {
			t.Fatalf("invented fork metadata: %+v", detail)
		}
		if detail.Kind == "exit" && detail.GroupDead != "unknown" {
			t.Fatalf("invented group death: %+v", detail)
		}
	}
	if _, _, err := decodeProcessEvent(make([]byte, 71)); err == nil {
		t.Fatal("accepted truncated record")
	}
}
