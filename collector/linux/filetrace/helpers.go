//go:build linux

package filetrace

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
)

func getenvAny(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func firstExistingPath(paths ...string) string {
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

func defaultObjCandidates(name string) []string {
	// Keep existing relative paths (repo-root execution), but also try relative
	// to the executable directory for systemd-friendly operation.
	rel := []string{
		filepath.Join("collector", "linux", name, "trace_bpfel.o"),
		filepath.Join("collector", "linux", name, "trace.bpf.o"),
	}
	exe, err := os.Executable()
	if err != nil {
		return rel
	}
	exeDir := filepath.Dir(exe)
	out := make([]string, 0, len(rel)*2)
	out = append(out, rel...)
	for _, p := range rel {
		out = append(out, filepath.Join(exeDir, p))
	}
	return out
}
