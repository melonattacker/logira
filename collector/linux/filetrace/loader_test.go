//go:build linux

package filetrace

import (
	"encoding/binary"
	"testing"
)

func TestRawFileEventMatchesCLayout(t *testing.T) {
	// struct file_event has an explicit pad before its filename, so the C and
	// Go decoders agree after adding fd and dirfd.
	if got := binary.Size(rawFileEvent{}); got != 296 {
		t.Fatalf("raw file event size=%d, want 296", got)
	}
}
