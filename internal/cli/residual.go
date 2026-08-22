package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/melonattacker/logira/internal/analyzer/residual"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

func ResidualCommand(ctx context.Context, args []string) error {
	_ = ctx
	fs := newFlagSet("residual", args, residualUsage)
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "emit the report as JSON")
	sel := "last"
	parseArgs := args
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		sel = args[0]
		parseArgs = args[1:]
	}
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("residual accepts at most one run selector")
	}
	if fs.NArg() == 1 {
		if sel != "last" {
			return fmt.Errorf("residual accepts at most one run selector")
		}
		sel = fs.Arg(0)
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	runID, runDir, err := runs.ResolveRunID(home, sel)
	if err != nil {
		return err
	}
	meta, err := runs.ReadMeta(runDir)
	if err != nil {
		return fmt.Errorf("read run metadata: %w", err)
	}
	if meta.EndTS == 0 {
		return fmt.Errorf("run %s is still running; residual analysis requires a completed run", runID)
	}
	if meta.AgentProvider == "" {
		return fmt.Errorf("run %s has no agent runtime telemetry; use 'logira run --agent codex -- codex exec --json ...'", runID)
	}
	if meta.AgentProvider != "codex" {
		return fmt.Errorf("run %s uses unsupported agent provider %q", runID, meta.AgentProvider)
	}

	events, err := readResidualEvents(runID, runDir)
	if err != nil {
		return err
	}
	report := residual.Analyze(meta, events)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			Meta   runs.Meta       `json:"meta"`
			Report residual.Report `json:"report"`
		}{Meta: meta, Report: report})
	}
	renderResidual(meta, report)
	return nil
}

func readResidualEvents(runID, runDir string) ([]storage.Event, error) {
	events, err := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		return nil, fmt.Errorf("read run events: %w", err)
	}
	return storage.Filter(events, storage.QueryOptions{RunID: runID}), nil
}

func renderResidual(meta runs.Meta, report residual.Report) {
	stdoutf("Action Residual: %s\n", report.RunID)
	stdoutf("  comparison: Codex runtime reports vs kernel-observed activity\n")
	stdoutf("  agent:      capture=%s interpretation=%s lines=%d/%d unknown=%d malformed=%d raw_truncated=%d append_failures=%d\n",
		meta.Coverage.Agent.Capture, meta.Coverage.Agent.Interpretation,
		meta.Coverage.Agent.LinesPersisted, meta.Coverage.Agent.LinesSeen,
		meta.Coverage.Agent.UnknownSchema, meta.Coverage.Agent.Malformed,
		meta.Coverage.Agent.RawTruncated, meta.Coverage.Agent.AppendFailures)
	renderKernelCoverage("process", meta.Coverage.Process)
	renderKernelCoverage("file", meta.Coverage.File)
	renderKernelCoverage("network", meta.Coverage.Network)
	stdoutf("  sandbox:    availability=%s\n", meta.Coverage.SandboxDecisions.Availability)

	stdoutln("\nFindings:")
	if len(report.Findings) == 0 {
		stdoutln("(none)")
	}
	for _, f := range report.Findings {
		label := string(f.Classification)
		if f.Confidence != "" {
			label += " confidence=" + f.Confidence
		}
		stdoutf("- %s\n", label)
		if f.Command != "" {
			stdoutf("  reported: %s", f.Command)
			if f.ItemID != "" {
				stdoutf(" (item=%s)", f.ItemID)
			}
			stdoutln()
		}
		if f.ExecSummary != "" {
			stdoutf("  observed: %s (pid=%d seq=%d)\n", f.ExecSummary, f.PID, f.ExecSeq)
		}
		if f.Reason != "" {
			stdoutf("  reason:   %s\n", f.Reason)
		}
	}

	stdoutln("\nTotals:")
	for _, class := range []residual.Classification{
		residual.Matched,
		residual.ReportedNotObserved,
		residual.ObservedNotReported,
		residual.Blocked,
		residual.Unobservable,
	} {
		stdoutf("  %-24s %d\n", class, report.Counts[class])
	}
	stdoutln("\nThese findings describe observational consistency; they are not an intent, safety, or maliciousness score.")
}

func renderKernelCoverage(name string, coverage runs.KernelCoverage) {
	loss := coverage.KnownLoss
	stdoutf("  %-11s availability=%s capture=%s loss={collector_forward:%d session_queue:%d persistence:%d}\n",
		name+":", coverage.Availability, coverage.Capture,
		loss.CollectorForwardDropped, loss.SessionQueueDropped, loss.PersistenceFailures)
}

func residualUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	_, _ = fmt.Fprintf(w, "%s residual: compare Codex runtime reports with kernel-observed actions\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s residual [last|<run-id>] [--json]\n\n", prog)
	_, _ = fmt.Fprintln(w, "Notes:")
	_, _ = fmt.Fprintln(w, "  Only completed runs captured with --agent codex are supported in v0.")
	_, _ = fmt.Fprintln(w, "  Results measure observational consistency, not model or user intent.")
	_, _ = fmt.Fprintln(w, "  Kernel capture 'complete' means Logira knows of no loss after its collector boundary.")
	_, _ = fmt.Fprintln(w, "  It does not prove that the underlying kernel/BPF path was globally lossless.")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "Flags:")
	fs.PrintDefaults()
}
