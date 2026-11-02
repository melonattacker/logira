package runs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyMetadataWithoutCoverageRemainsReadable(t *testing.T) {
	dir := t.TempDir()
	raw := []byte(`{"run_id":"legacy","version":3,"command":"echo hi","start_ts":1,"end_ts":2}`)
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	meta, err := ReadMeta(dir)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Version != 3 || meta.Command != "echo hi" || meta.RunID != "legacy" {
		t.Fatalf("legacy fields changed: %+v", meta)
	}
	for _, c := range []KernelCoverage{meta.Coverage.Process, meta.Coverage.File, meta.Coverage.Network} {
		if c.Capture == "complete" || c.Availability == "available" {
			t.Fatalf("invented old coverage: %+v", c)
		}
	}
}
