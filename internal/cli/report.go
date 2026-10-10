package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/melonattacker/logira/internal/presentation/actionview"
	"github.com/melonattacker/logira/internal/presentation/htmlreport"
	"github.com/melonattacker/logira/internal/runs"
)

func ReportCommand(ctx context.Context, args []string) error {
	_ = ctx
	selector, output, force, err := parseReportArgs(args)
	if err != nil {
		return err
	}

	home, err := runs.EnsureHome()
	if err != nil {
		return err
	}
	runID, runDir, err := runs.ResolveRunID(home, selector)
	if err != nil {
		return err
	}
	meta, err := runs.ReadMeta(runDir)
	if err != nil {
		return fmt.Errorf("read run metadata: %w", err)
	}
	if err := validateHTMLReportRun(meta, runID); err != nil {
		return err
	}
	events, err := readResidualEvents(runID, runDir)
	if err != nil {
		return err
	}
	view, err := actionview.Build(meta, events)
	if err != nil {
		return fmt.Errorf("build agent action view: %w", err)
	}

	var rendered bytes.Buffer
	if err := htmlreport.Render(&rendered, htmlreport.Build(view)); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	output = resolveReportOutputPath(output, runID)
	if err := writeReportFile(output, rendered.Bytes(), force); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file %q already exists; use --force or choose --output: %w", output, err)
		}
		return fmt.Errorf("write HTML report %q: %w", output, err)
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	_, err = fmt.Fprintln(os.Stdout, filepath.Clean(absOutput))
	return err
}

func parseReportArgs(args []string) (selector, output string, force bool, err error) {
	fs := newFlagSet("report", args, reportUsage)
	var html bool
	fs.BoolVar(&html, "html", false, "generate standalone HTML (the current default)")
	fs.BoolVar(&force, "force", false, "replace an existing output file")
	fs.StringVar(&output, "output", "", "output file path")
	fs.StringVar(&output, "o", "", "output file path (shorthand)")

	selector = "last"
	parseArgs := args
	selectorSpecified := false
	if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		selector = parseArgs[0]
		parseArgs = parseArgs[1:]
		selectorSpecified = true
	}
	if err := fs.Parse(parseArgs); err != nil {
		return "", "", false, err
	}
	if fs.NArg() > 1 || fs.NArg() == 1 && selectorSpecified {
		return "", "", false, fmt.Errorf("report accepts at most one run selector")
	}
	if fs.NArg() == 1 {
		selector = fs.Arg(0)
	}
	_ = html // HTML is the sole v0 format; the explicit flag is compatibility-friendly.
	return selector, output, force, nil
}

func resolveReportOutputPath(output, runID string) string {
	if strings.TrimSpace(output) == "" {
		return "logira-report-" + runID + ".html"
	}
	return output
}

func validateHTMLReportRun(meta runs.Meta, runID string) error {
	if meta.EndTS == 0 {
		return fmt.Errorf("run %s is still running; HTML reports require a completed run", runID)
	}
	if meta.AgentProvider == "" {
		return fmt.Errorf("run %s has no supported agent runtime telemetry; HTML reports currently require a completed Codex agent run", runID)
	}
	if meta.AgentProvider != "codex" {
		return fmt.Errorf("run %s uses unsupported agent provider %q; HTML reports currently support Codex", runID, meta.AgentProvider)
	}
	return nil
}

func writeReportFile(path string, data []byte, force bool) error {
	if !force {
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // user-selected report destination.
		if err != nil {
			return err
		}
		ok := false
		defer func() {
			_ = file.Close()
			if !ok {
				_ = os.Remove(path)
			}
		}()
		if _, err := io.Copy(file, bytes.NewReader(data)); err != nil {
			return err
		}
		if err := file.Sync(); err != nil {
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
		ok = true
		return nil
	}

	if info, err := os.Lstat(path); err == nil && info.IsDir() {
		return fmt.Errorf("destination is a directory")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".logira-report-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := io.Copy(tmp, bytes.NewReader(data)); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func reportUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	_, _ = fmt.Fprintf(w, "%s report: generate a standalone local HTML report\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s report [last|<run-id>] [--html] [-o|--output <path>] [--force]\n\n", prog)
	_, _ = fmt.Fprintln(w, "Examples:")
	_, _ = fmt.Fprintf(w, "  %s report last\n", prog)
	_, _ = fmt.Fprintf(w, "  %s report last --html\n", prog)
	_, _ = fmt.Fprintf(w, "  %s report last --output ./audit.html\n", prog)
	_, _ = fmt.Fprintf(w, "  %s report 20260829-044241-codex --force\n\n", prog)
	_, _ = fmt.Fprintln(w, "Notes:")
	_, _ = fmt.Fprintln(w, "  HTML is the default and only v0 report format.")
	_, _ = fmt.Fprintln(w, "  The default output is ./logira-report-<run-id>.html.")
	_, _ = fmt.Fprintln(w, "  Existing files are never replaced unless --force is supplied.")
	_, _ = fmt.Fprintln(w, "  V0 reports require a completed Codex agent run.")
	_, _ = fmt.Fprintln(w, "\nFlags:")
	fs.PrintDefaults()
}
