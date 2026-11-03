package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/melonattacker/logira/internal/analysis/episode"
	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/presentation/htmlreport"
)

const maxHTMLReportBytes int64 = 64 << 20

var errReportTooLarge = errors.New("rendered HTML report exceeds 64 MiB limit")

type optionalExecSeq struct {
	value int64
	set   bool
}

func (v *optionalExecSeq) String() string {
	if v == nil || !v.set {
		return ""
	}
	return strconv.FormatInt(v.value, 10)
}

func (v *optionalExecSeq) Set(raw string) error {
	parsed, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid exec sequence %q: %w", raw, err)
	}
	v.value, v.set = parsed, true
	return nil
}

type reportOptions struct {
	selector string
	output   string
	force    bool
	execSeq  optionalExecSeq
}

func ReportCommand(ctx context.Context, args []string) error {
	return reportCommand(ctx, args, os.Stdout)
}

func reportCommand(ctx context.Context, args []string, stdout io.Writer) error {
	opts, err := parseReportArgs(args)
	if err != nil {
		return err
	}
	analysis, err := loadAnalysisRun(ctx, opts.selector)
	if err != nil {
		return err
	}
	var ep *episode.Episode
	if opts.execSeq.set {
		if opts.execSeq.value <= 0 {
			return fmt.Errorf("--exec-seq must be a positive sequence number")
		}
		built, err := episode.Build(analysis.Meta, opts.execSeq.value, analysis.Graph)
		if err != nil {
			return err
		}
		built.AnalysisSource.Events = analysis.Snapshot.EventSource
		built.AnalysisSource.Metadata = analysis.Snapshot.MetadataSource
		if analysis.Snapshot.MetadataSource == "missing" {
			built.Limitations = append(built.Limitations, processgraph.Issue{Code: "missing_run_metadata"})
			episode.SortLimitations(built.Limitations)
		}
		ep = &built
	}
	report, err := htmlreport.Build(htmlreport.BuildInput{
		RunID: analysis.RunID, Meta: analysis.Meta, MetadataSource: analysis.Snapshot.MetadataSource,
		EventSource: analysis.Snapshot.EventSource, Events: analysis.Snapshot.Events, Graph: analysis.Graph, Episode: ep,
	})
	if err != nil {
		return fmt.Errorf("build HTML report: %w", err)
	}
	output := reportOutputPath(opts.output, analysis.RunID, opts.execSeq)
	if err := writeReportFile(output, opts.force, func(w io.Writer) error { return htmlreport.Render(w, report) }); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output file %q already exists; use --force or choose --output: %w", output, err)
		}
		return fmt.Errorf("write HTML report %q: %w", output, err)
	}
	abs, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	_, err = fmt.Fprintln(stdout, filepath.Clean(abs))
	return err
}

func parseReportArgs(args []string) (reportOptions, error) {
	opts := reportOptions{selector: "last"}
	fs := newFlagSet("report", args, reportUsage)
	fs.Var(&opts.execSeq, "exec-seq", "selected root exec sequence (positive integer)")
	fs.StringVar(&opts.output, "output", "", "output file path")
	fs.StringVar(&opts.output, "o", "", "output file path (shorthand)")
	fs.BoolVar(&opts.force, "force", false, "replace an existing regular output file")
	parseArgs := args
	selectorSpecified := false
	if len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		opts.selector = parseArgs[0]
		parseArgs = parseArgs[1:]
		selectorSpecified = true
	}
	if err := fs.Parse(parseArgs); err != nil {
		return reportOptions{}, err
	}
	if fs.NArg() > 1 || (selectorSpecified && fs.NArg() > 0) {
		return reportOptions{}, fmt.Errorf("report accepts at most one run selector; see 'logira report --help'")
	}
	if fs.NArg() == 1 {
		opts.selector = fs.Arg(0)
	}
	if opts.execSeq.set && opts.execSeq.value <= 0 {
		return reportOptions{}, fmt.Errorf("--exec-seq must be a positive sequence number")
	}
	return opts, nil
}

func reportOutputPath(output, runID string, seq optionalExecSeq) string {
	if strings.TrimSpace(output) != "" {
		return output
	}
	if seq.set {
		return fmt.Sprintf("logira-report-%s-exec-%d.html", runID, seq.value)
	}
	return fmt.Sprintf("logira-report-%s.html", runID)
}

type reportLimitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *reportLimitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > w.remaining {
		if w.remaining <= 0 {
			return 0, errReportTooLarge
		}
		n, err := w.w.Write(p[:w.remaining])
		w.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		return n, errReportTooLarge
	}
	n, err := w.w.Write(p)
	w.remaining -= int64(n)
	return n, err
}

// writeReportFile renders to a private same-directory temporary file before it
// installs a complete report. A destination symlink is never followed.
func writeReportFile(path string, force bool, render func(io.Writer) error) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".logira-report-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	installed := false
	defer func() {
		_ = tmp.Close()
		if !installed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	limited := &reportLimitWriter{w: tmp, remaining: maxHTMLReportBytes}
	if err := render(limited); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	if !force {
		if err := os.Link(tmpPath, path); err != nil {
			return err
		}
		if err := os.Remove(tmpPath); err != nil {
			_ = os.Remove(path)
			return err
		}
		installed = true
		return nil
	}
	if info, err := os.Lstat(path); err == nil {
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("refusing to replace destination symlink")
		case !info.Mode().IsRegular():
			return fmt.Errorf("refusing to replace non-regular destination")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	installed = true
	return nil
}

func reportUsage(w io.Writer, fs *flag.FlagSet) {
	prog := progName()
	_, _ = fmt.Fprintf(w, "%s report: generate a standalone offline HTML audit report\n\n", prog)
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintf(w, "  %s report [last|<run-id>] [--exec-seq <seq>] [-o|--output <path>] [--force]\n\n", prog)
	_, _ = fmt.Fprintln(w, "Examples:")
	_, _ = fmt.Fprintf(w, "  %s report last\n", prog)
	_, _ = fmt.Fprintf(w, "  %s report last --exec-seq 11\n", prog)
	_, _ = fmt.Fprintf(w, "  %s report last --exec-seq 11 --output ./audit.html\n\n", prog)
	_, _ = fmt.Fprintln(w, "The default report is a Run Overview. --exec-seq adds a selected Episode Detail.")
	_, _ = fmt.Fprintln(w, "Existing files and symlinks are not replaced without --force; --force still rejects symlinks.")
	_, _ = fmt.Fprintln(w, "\nFlags:")
	fs.PrintDefaults()
}
