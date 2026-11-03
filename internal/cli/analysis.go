package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

type loadedAnalysis struct {
	RunID    string
	RunDir   string
	Meta     runs.Meta
	Snapshot storage.AnalysisSnapshot
	Graph    *processgraph.Graph
}

func loadAnalysisRun(ctx context.Context, selector string) (loadedAnalysis, error) {
	var out loadedAnalysis
	runID, runDir, err := runs.ResolveExistingRun(selector)
	if err != nil {
		return out, err
	}
	snapshot, err := storage.ReadAnalysisSnapshot(ctx, runDir, runID)
	if err != nil {
		return out, err
	}
	meta := runs.Meta{RunID: runID}
	if len(snapshot.MetaJSON) > 0 {
		if strings.TrimSpace(string(snapshot.MetaJSON)) == "null" {
			return out, fmt.Errorf("%s metadata must be an object", snapshot.MetadataSource)
		}
		if err := json.Unmarshal(snapshot.MetaJSON, &meta); err != nil {
			return out, fmt.Errorf("decode %s metadata: %w", snapshot.MetadataSource, err)
		}
	}
	if meta.RunID != "" && meta.RunID != runID {
		return out, fmt.Errorf("metadata run_id %q does not match %q", meta.RunID, runID)
	}
	meta.RunID = runID
	g, err := processgraph.Build(runID, snapshot.Events)
	if err != nil {
		return out, err
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	return loadedAnalysis{RunID: runID, RunDir: runDir, Meta: meta, Snapshot: snapshot, Graph: g}, nil
}
