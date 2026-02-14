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
			ids = append(ids, e.Name())
		}
	}
	if len(ids) == 0 {
		return "", fmt.Errorf("no runs found under %s", base)
	}
	sort.Strings(ids)
	return ids[len(ids)-1], nil
}
