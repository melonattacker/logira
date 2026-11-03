package runs

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func RunDir(home, runID string) string {
	return filepath.Join(home, "runs", runID)
}

// ResolveExistingRun locates saved input without EnsureHome's mkdir/SQLite
// probes. Only offline Episode analysis uses this helper; capture is unchanged.
func ResolveExistingRun(sel string) (string, string, error) {
	home, err := HomeDir()
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(os.Getenv("LOGIRA_HOME")) != "" || strings.TrimSpace(os.Getenv("logira_HOME")) != "" {
		return ResolveRunID(home, sel)
	}
	var firstErr error
	for _, candidate := range homeCandidates(home) {
		id, dir, err := ResolveRunID(candidate, sel)
		if err == nil {
			return id, dir, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return "", "", firstErr
}

// ResolveRunID resolves "last" or an explicit run id into a run directory.
func ResolveRunID(home, sel string) (runID string, runDir string, err error) {
	sel = strings.TrimSpace(sel)
	if sel == "" || sel == "last" {
		id, err := LastRunID(home)
		if err != nil {
			return "", "", err
		}
		return id, RunDir(home, id), nil
	}
	if err := ValidateRunID(sel); err != nil {
		return "", "", err
	}
	dir := RunDir(home, sel)
	if _, err := os.Stat(dir); err != nil {
		return "", "", fmt.Errorf("run %q not found: %w", sel, err)
	}
	return sel, dir, nil
}

func LastRunID(home string) (string, error) {
	base := filepath.Join(home, "runs")
	ents, err := os.ReadDir(base)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", base, err)
	}
	ids := make([]string, 0, len(ents))
	for _, e := range ents {
		if e.IsDir() {
			if ValidateRunID(e.Name()) == nil {
				ids = append(ids, e.Name())
			}
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no runs found under %s", base)
	}
	sort.Strings(ids)
	return ids[len(ids)-1], nil
}
