package cli

import (
	"testing"

	"github.com/melonattacker/logira/internal/storage"
)

func TestParseProcessEventType(t *testing.T) {
	got, err := parseEventType("process")
	if err != nil || got != storage.TypeProcess {
		t.Fatalf("parseEventType(process)=(%q, %v)", got, err)
	}
}
