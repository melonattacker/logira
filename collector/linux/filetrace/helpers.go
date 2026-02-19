//go:build linux

package filetrace

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
	rel := []string{
		filepath.Join("collector", "linux", name, "trace_bpfel.o"),
		filepath.Join("collector", "linux", name, "trace.bpf.o"),
		filepath.Join(name, "trace_bpfel.o"),
		filepath.Join(name, "trace.bpf.o"),
		"trace_bpfel.o",
		"trace.bpf.o",
	}

	out := make([]string, 0, len(rel)*3+2)
	out = append(out, rel...)

	// Package-local absolute path works in `go test` where CWD can be package-scoped.
	if _, file, _, ok := runtime.Caller(0); ok {
		dir := filepath.Dir(file)
		out = append(out,
			filepath.Join(dir, "trace_bpfel.o"),
			filepath.Join(dir, "trace.bpf.o"),
		)
	}

	// Executable-relative paths help systemd/install layouts.
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, p := range rel {
			out = append(out, filepath.Join(exeDir, p))
		}
	}

	return uniquePaths(out)
}

func uniquePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}
