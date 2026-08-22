//go:build linux

package nettrace

import (
	"encoding/binary"
	"testing"
)

func TestDecodeNetEventCLayout(t *testing.T) {
	// Mirrors struct net_event from _trace.bpf.c, including the four bytes of
	// alignment before the signed 64-bit byte count.
	rawBytes := make([]byte, 48)
	binary.LittleEndian.PutUint64(rawBytes[0:8], 123456789)
	binary.LittleEndian.PutUint64(rawBytes[8:16], 987654321)
	binary.LittleEndian.PutUint32(rawBytes[16:20], 4242)
	binary.LittleEndian.PutUint32(rawBytes[20:24], 1000)
	rawBytes[24] = 2 // send
	rawBytes[25] = 6 // TCP
	copy(rawBytes[28:32], []byte{203, 0, 113, 7})
	// The BPF event preserves sockaddr/network byte order for the port.
	binary.BigEndian.PutUint16(rawBytes[32:34], 443)
	binary.LittleEndian.PutUint64(rawBytes[40:48], 29)

	raw, err := decodeNetEvent(rawBytes)
	if err != nil {
		t.Fatal(err)
	}
	if raw.TSNS != 123456789 || raw.CgroupID != 987654321 || raw.PID != 4242 || raw.UID != 1000 {
		t.Fatalf("identity fields decoded incorrectly: %+v", raw)
	}
	if got := ipv4String(raw.IP4); got != "203.0.113.7" {
		t.Fatalf("destination IP = %q", got)
	}
	if raw.Port != 443 {
		t.Fatalf("destination port = %d, want 443", raw.Port)
	}
	if raw.Bytes != 29 {
		t.Fatalf("bytes = %d, want 29", raw.Bytes)
	}
}

func TestDecodeNetEventRejectsWrongABISize(t *testing.T) {
	if _, err := decodeNetEvent(make([]byte, 44)); err == nil {
		t.Fatal("expected obsolete unpadded event size to be rejected")
	}
}
