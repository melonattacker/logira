//go:build linux

package nettrace

import (
	"encoding/binary"
	"testing"
)

func TestDecodeIPv4WireFixturesAndPortBytes(t *testing.T) {
	tests := []struct {
		name      string
		address   []byte
		port      uint16
		portBytes [2]byte
		wantIP    string
	}{
		{name: "https", address: []byte{1, 2, 3, 4}, port: 443, portBytes: [2]byte{0x01, 0xbb}, wantIP: "1.2.3.4"},
		{name: "localhost", address: []byte{127, 0, 0, 1}, port: 18080, portBytes: [2]byte{0x46, 0xa0}, wantIP: "127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sample := netWireFixture(2, tt.address, tt.port)
			if got := [2]byte{sample[24], sample[25]}; got != tt.portBytes {
				t.Fatalf("port bytes=%#v, want %#v", got, tt.portBytes)
			}
			raw, err := decodeNetEvent(sample)
			if err != nil {
				t.Fatal(err)
			}
			if got := addressString(raw.Family, raw.Address); got != tt.wantIP {
				t.Fatalf("IP=%q, want %q", got, tt.wantIP)
			}
			if raw.Port != tt.port {
				t.Fatalf("port=%d, want %d", raw.Port, tt.port)
			}
			assertNetScalars(t, raw)
		})
	}
}

func TestDecodeIPv6WireFixture(t *testing.T) {
	address := make([]byte, 16)
	address[15] = 1
	sample := netWireFixture(10, address, 18080)
	if sample[24] != 0x46 || sample[25] != 0xa0 {
		t.Fatalf("port bytes=%#v", sample[24:26])
	}
	raw, err := decodeNetEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if got := addressString(raw.Family, raw.Address); got != "::1" {
		t.Fatalf("IP=%q", got)
	}
	if raw.Port != 18080 {
		t.Fatalf("port=%d", raw.Port)
	}
}

func TestDecodeSignedByteCountTwoComplement(t *testing.T) {
	sample := netWireFixture(2, []byte{127, 0, 0, 1}, 443)
	binary.BigEndian.PutUint64(sample[64:72], ^uint64(6)) // -7 in two's complement
	raw, err := decodeNetEvent(sample)
	if err != nil {
		t.Fatal(err)
	}
	if raw.Bytes != -7 {
		t.Fatalf("bytes=%d", raw.Bytes)
	}
}

func TestDecodeNetEventRejectsSizeAndVersionDrift(t *testing.T) {
	if _, err := decodeNetEvent(make([]byte, netEventWireSize-1)); err == nil {
		t.Fatal("expected obsolete ABI size to be rejected")
	}
	sample := netWireFixture(2, []byte{1, 2, 3, 4}, 443)
	sample[0] = 2
	if _, err := decodeNetEvent(sample); err == nil {
		t.Fatal("expected unsupported ABI version to be rejected")
	}
}

func netWireFixture(family uint8, address []byte, port uint16) []byte {
	sample := make([]byte, netEventWireSize)
	sample[0] = 1 // ABI version
	sample[1] = 2 // send
	sample[2] = family
	sample[3] = 6 // TCP
	copy(sample[8:24], address)
	binary.BigEndian.PutUint16(sample[24:26], port)
	binary.BigEndian.PutUint64(sample[32:40], 123456789)
	binary.BigEndian.PutUint64(sample[40:48], 987654321)
	binary.BigEndian.PutUint32(sample[48:52], 4242)
	binary.BigEndian.PutUint32(sample[52:56], 4243)
	binary.BigEndian.PutUint32(sample[56:60], 4242)
	binary.BigEndian.PutUint32(sample[60:64], 1000)
	binary.BigEndian.PutUint64(sample[64:72], 29)
	return sample
}

func assertNetScalars(t *testing.T, raw rawNetEvent) {
	t.Helper()
	if raw.ABIVersion != 1 || raw.TSNS != 123456789 || raw.CgroupID != 987654321 || raw.PID != 4242 || raw.TID != 4243 || raw.TGID != 4242 || raw.UID != 1000 || raw.Bytes != 29 {
		t.Fatalf("identity/scalar fields decoded incorrectly: %+v", raw)
	}
}
