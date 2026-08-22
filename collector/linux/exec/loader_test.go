//go:build linux

package exectrace

import (
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
