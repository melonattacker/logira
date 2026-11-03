package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/melonattacker/logira/internal/analysis/episode"
	"github.com/melonattacker/logira/internal/analysis/processgraph"
)

func EpisodeCommand(ctx context.Context, args []string) error {
	return episodeCommand(ctx, args, os.Stdout)
}

func episodeCommand(ctx context.Context, args []string, w io.Writer) error {
	fs := newFlagSet("episode", args, episodeUsage)
	var seq int64
	var asJSON bool
	fs.Int64Var(&seq, "exec-seq", 0, "required root exec sequence (positive integer)")
	fs.BoolVar(&asJSON, "json", false, "emit one structured Episode JSON object")
	sel := "last"
	explicit := false
	parseArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sel = args[0]
		explicit = true
		parseArgs = args[1:]
	}
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (explicit && fs.NArg() > 0) {
		return fmt.Errorf("episode accepts one run selector; see 'logira episode --help'")
	}
	if fs.NArg() == 1 {
		sel = fs.Arg(0)
	}
	if seq <= 0 {
		return fmt.Errorf("episode requires --exec-seq with a positive integer; find one with 'logira query %s --type exec'", sel)
	}
	analysis, err := loadAnalysisRun(ctx, sel)
	if err != nil {
		return err
	}
	ep, err := episode.Build(analysis.Meta, seq, analysis.Graph)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	ep.AnalysisSource.Events = analysis.Snapshot.EventSource
	ep.AnalysisSource.Metadata = analysis.Snapshot.MetadataSource
	if analysis.Snapshot.MetadataSource == "missing" {
		ep.Limitations = append(ep.Limitations, processgraph.Issue{Code: "missing_run_metadata"})
		episode.SortLimitations(ep.Limitations)
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(ep)
	}
	return renderEpisode(w, ep)
}

func renderEpisode(w io.Writer, ep episode.Episode) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Run %s  Episode root exec=%d\n", ep.RunID, ep.RootExecSeq)
	fmt.Fprintf(&b, "Root: %s\n", episodeCommandText(ep.RootExec))
	fmt.Fprintf(&b, "Members: %d tasks, %d observed execs\n", ep.Summary.Processes, ep.Summary.Execs)
	for _, member := range ep.ProcessMembers {
		fmt.Fprintf(&b, "  %s identities=", member.ID)
		for i, id := range member.Identities {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "tid=%d/tgid=%d", id.TID, id.TGID)
		}
		fmt.Fprintf(&b, " entry=%s:%d\n", member.EntryKind, member.EntrySeq)
	}
	for _, ex := range ep.ExecMembers {
		generation := "unknown"
		if ex.Generation != nil {
			generation = fmt.Sprint(*ex.Generation)
		}
		fmt.Fprintf(&b, "  exec=%d task=%s generation=%s %s\n", ex.Event.Seq, ex.TaskID, generation, episodeCommandText(ex))
	}
	for _, v := range []struct {
		name string
		c    episode.Counts
	}{{"File", ep.Summary.File}, {"Network", ep.Summary.Network}} {
		fmt.Fprintf(&b, "%s: %d attributed, %d uncertain; run remainder: %d unrelated, %d unattributable (%d retained total)\n", v.name, v.c.Attributed, v.c.Uncertain, v.c.Unrelated, v.c.Unattributable, v.c.Observed)
	}
	b.WriteString("Coverage is run-scoped and unverified; only retained observations are analyzed.\nCaveats:")
	counts := map[string]int{}
	order := []string{}
	for _, issue := range ep.Limitations {
		if counts[issue.Code] == 0 {
			order = append(order, issue.Code)
		}
		counts[issue.Code]++
	}
	for _, code := range order {
		fmt.Fprintf(&b, "\n  %s (%d)", code, counts[code])
	}
	b.WriteByte('\n')
	_, err := io.WriteString(w, b.String())
	return err
}

func episodeCommandText(ex processgraph.Exec) string {
	if len(ex.Detail.Argv) > 0 {
		args := make([]string, len(ex.Detail.Argv))
		for i, arg := range ex.Detail.Argv {
			args[i] = fmt.Sprintf("%q", arg)
		}
		return strings.Join(args, " ")
	}
	if ex.Detail.Filename != "" {
		return fmt.Sprintf("%q", ex.Detail.Filename)
	}
	return "(executable/arguments unknown)"
}

func episodeUsage(w io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintf(w, "Usage: %s episode [last|<run-id>] --exec-seq <seq> [--json]\n\nReconstruct a selected observed execution lineage; no security judgment is made.\n\nFlags:\n", progName())
	fs.PrintDefaults()
}
