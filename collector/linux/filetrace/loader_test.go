//go:build linux

package filetrace

import (
	"encoding/binary"
	"testing"
)

func TestRawFileEventMatchesCLayout(t *testing.T) {
	// The lifecycle ABI has explicit padding before ret and both path arrays.
	if got := binary.Size(rawFileEvent{}); got != 592 {
		t.Fatalf("raw file event size=%d, want 592", got)
	}
}

func TestDecodeFileEventKnownRawOpenatFixture(t *testing.T) {
	sample := make([]byte, 592)
	binary.LittleEndian.PutUint64(sample[0:8], 1234)
	binary.LittleEndian.PutUint64(sample[8:16], 42)
	binary.LittleEndian.PutUint64(sample[16:24], 1200)
	binary.LittleEndian.PutUint32(sample[24:28], 100)
	binary.LittleEndian.PutUint32(sample[28:32], 101)
	binary.LittleEndian.PutUint32(sample[32:36], 1000)
	binary.LittleEndian.PutUint32(sample[36:40], 1)
	binary.LittleEndian.PutUint32(sample[40:44], 1)
	binary.LittleEndian.PutUint32(sample[44:48], 0xc0) // O_CREAT|O_EXCL
	binary.LittleEndian.PutUint32(sample[48:52], 7)
	binary.LittleEndian.PutUint32(sample[52:56], 0xffffff9c)
	sample[72] = 1
	copy(sample[80:336], []byte("fixture.txt\x00"))

	raw, err := decodeFileEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if raw.TGID != 100 || raw.TID != 101 || raw.FD != 7 || raw.DirFD != -100 || cString(raw.Path[:]) != "fixture.txt" {
		t.Fatalf("decoded=%+v path=%q", raw, cString(raw.Path[:]))
	}
	if got := opFromRaw(raw); got != "create" {
		t.Fatalf("op=%q", got)
	}
}

func TestOpenFlagsPreserveCreateUncertainty(t *testing.T) {
	for flags, want := range map[uint32]string{
		0xc0:  "create",
		0x40:  "create_or_open",
		0x200: "modify",
		0:     "open",
	} {
		if got := opFromFlags(flags); got != want {
			t.Fatalf("opFromFlags(%#x)=%q, want %q", flags, got, want)
		}
	}
}

func TestDecodeFileEventRejectsLayoutDrift(t *testing.T) {
	if _, err := decodeFileEvent(make([]byte, 591)); err == nil {
		t.Fatal("expected size error")
	}
}
