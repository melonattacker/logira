//go:build linux

package filetrace

import "testing"

func TestOpFromFlags(t *testing.T) {
	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{name: "read only", flags: 0, want: "open"},
		{name: "write only", flags: 1, want: "modify"},
		{name: "read write", flags: 2, want: "modify"},
		{name: "create", flags: 0x40, want: "create"},
		{name: "truncate", flags: 0x200, want: "modify"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := opFromFlags(tc.flags); got != tc.want {
				t.Fatalf("opFromFlags(%#x)=%q want %q", tc.flags, got, tc.want)
			}
		})
	}
}
