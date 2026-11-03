// Package htmlreport builds and renders a generic, offline audit report from
// retained Run observations and, optionally, one selected Execution Episode.
// It is a presentation layer: process identity, membership, and attribution
// decisions remain owned by processgraph and episode.
package htmlreport

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/melonattacker/logira/internal/analysis/episode"
	"github.com/melonattacker/logira/internal/analysis/processgraph"
	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

const (
	maxExecRows           = 500
	maxTaskRows           = 2000
	maxFileGroups         = 1000
	maxNetworkGroups      = 500
	maxUncertainGroups    = 500
	maxDetectionGroups    = 250
	maxDetectionEvidence  = 20
	maxSourceSeqsPerGroup = 100
	maxRawPreviewBytes    = 8 * 1024
	maxDisplayTextBytes   = 4 * 1024
	maxVisualTreeDepth    = 24
)

// BuildInput contains already-loaded analysis data. Episode must be nil for a
// Run Overview. Build never reads or writes Run storage.
type BuildInput struct {
	RunID          string
	Meta           runs.Meta
	MetadataSource string
	EventSource    string
	Events         []storage.Event
	Graph          *processgraph.Graph
	Episode        *episode.Episode
}

type Report struct {
	Run              RunOverview
	Coverage         []CoverageItem
	CoverageNotes    []string
	Execs            []ExecRow
	ExecTotal        int
	ExecOmitted      int
	Limitations      []IssueGroup
	Detections       []DetectionGroup
	DetectionTotal   int
	DetectionOmitted int
	Episode          *EpisodeView
	Commands         Commands
	Limits           DisplayLimits
}

type RunOverview struct {
	ID             string
	Mode           string
	Command        string
	CommandOmitted int
	Argv           string
	ArgvOmitted    int
	Started        string
	Ended          string
	Duration       string
	State          string
	StateClass     string
	Tool           string
	CWD            string
	Version        string
	EventSource    string
	MetadataSource string
	MaxSeq         int64
	Counts         ObservationCounts
}

type ObservationCounts struct {
	Exec      int
	Process   int
	File      int
	Network   int
	Detection int
	Other     int
	Tasks     int
}

type CoverageItem struct {
	Name         string
	Availability string
	Capture      string
	KnownLoss    uint64
	LossDetail   string
	Class        string
}

type ExecRow struct {
	Seq         int64
	Timestamp   string
	TaskID      string
	Generation  string
	Identities  string
	Filename    string
	Argv        string
	ArgvOmitted int
	RawJSON     string
	RawOmitted  int
}

type IssueGroup struct {
	Code       string
	Message    string
	Count      int
	References string
	RefOmitted int
	Scope      string
}

type DetectionGroup struct {
	Severity      string
	SeverityClass string
	RuleID        string
	Message       string
	Count         int
	First         string
	Last          string
	Evidence      []DetectionEvidence
	EvidenceMore  int
}

type DetectionEvidence struct {
	DetectionSeq int64
	RelatedSeq   int64
	RelatedType  string
	LinkState    string
	Summary      string
	RawJSON      string
	RawOmitted   int
}

type EpisodeView struct {
	Root           ExecRow
	Tasks          []TaskRow
	TaskTotal      int
	TaskOmitted    int
	Relationships  []RelationshipRow
	File           ActivitySection[FileGroup]
	Network        ActivitySection[NetworkGroup]
	Uncertain      ActivitySection[UncertainGroup]
	FileCounts     episode.Counts
	NetworkCounts  episode.Counts
	Unattributable []ReasonCount
	Limitations    []IssueGroup
	AnalysisSource episode.Source
}

type TaskRow struct {
	Depth            int
	Indent           string
	DepthNote        string
	TaskID           string
	Entry            string
	Identities       string
	ForkSeqs         string
	RekeySeqs        string
	ExitSeqs         string
	Execs            []TaskExec
	ForkOnly         bool
	Incoming         string
	CloneKind        string
	Relationship     string
	FileCount        int
	NetworkCount     int
	IdentityConflict bool
	GroupDead        string
}

type TaskExec struct {
	Seq         int64
	Generation  string
	Filename    string
	Argv        string
	ArgvOmitted int
}

type RelationshipRow struct {
	Seq        int64
	Parent     string
	Child      string
	CloneKind  string
	Resolution string
	Confirmed  bool
}

type ActivitySection[T any] struct {
	Observed      int
	GroupTotal    int
	Groups        []T
	OmittedGroups int
	OmittedEvents int
}

type FileGroup struct {
	TaskID         string
	ExecRef        string
	Attribution    string
	Operation      string
	Path           string
	Path2          string
	AccessMode     string
	Syscall        string
	Correlation    string
	PathResolution string
	ReturnValue    string
	Bytes          string
	Count          int
	SourceSeqs     string
	SourceMore     int
	RawJSON        string
	RawOmitted     int
}

type NetworkGroup struct {
	TaskID      string
	ExecRef     string
	Attribution string
	Operation   string
	Protocol    string
	Destination string
	State       string
	Bytes       string
	Count       int
	SourceSeqs  string
	SourceMore  int
	RawJSON     string
	RawOmitted  int
}

type UncertainGroup struct {
	Type       string
	Basis      string
	Reason     string
	TaskID     string
	Summary    string
	Count      int
	SourceSeqs string
	SourceMore int
	RawJSON    string
	RawOmitted int
}

type ReasonCount struct {
	Reason string
	Count  int
}

type Commands struct {
	Execs      string
	Overview   string
	Episode    string
	File       string
	Network    string
	Detections string
}

type DisplayLimits struct {
	ExecRows        int
	TaskRows        int
	FileGroups      int
	NetworkGroups   int
	UncertainGroups int
	DetectionGroups int
	SourceSeqs      int
	RawPreviewBytes int
}

func Build(in BuildInput) (Report, error) {
	if strings.TrimSpace(in.RunID) == "" {
		return Report{}, fmt.Errorf("report run ID is required")
	}
	if in.Graph == nil {
		return Report{}, fmt.Errorf("process graph is required")
	}
	if in.Graph.RunID != in.RunID {
		return Report{}, fmt.Errorf("process graph run_id %q does not match %q", in.Graph.RunID, in.RunID)
	}
	if in.Episode != nil && in.Episode.RunID != in.RunID {
		return Report{}, fmt.Errorf("episode run_id %q does not match %q", in.Episode.RunID, in.RunID)
	}

	r := Report{
		Run:           buildRun(in),
		Coverage:      buildCoverage(in.Meta.Coverage),
		CoverageNotes: coverageNotes(in.Meta, in.MetadataSource),
		Commands: Commands{
			Execs:      fmt.Sprintf("logira query %s --type exec", in.RunID),
			Overview:   fmt.Sprintf("logira report %s", in.RunID),
			File:       fmt.Sprintf("logira query %s --type file --limit 100", in.RunID),
			Network:    fmt.Sprintf("logira query %s --type net --limit 100", in.RunID),
			Detections: fmt.Sprintf("logira query %s --type detection --limit 100", in.RunID),
		},
		Limits: DisplayLimits{maxExecRows, maxTaskRows, maxFileGroups, maxNetworkGroups, maxUncertainGroups, maxDetectionGroups, maxSourceSeqsPerGroup, maxRawPreviewBytes},
	}
	r.Execs, r.ExecTotal, r.ExecOmitted = buildExecRows(in.Graph)
	r.Limitations = groupIssues(in.Graph.Issues, "Run reconstruction")

	attributed, uncertain := map[int64]bool{}, map[int64]bool{}
	if in.Episode != nil {
		view, err := buildEpisode(*in.Episode, in.Graph)
		if err != nil {
			return Report{}, err
		}
		r.Episode = &view
		r.Run.Mode = "Episode Detail"
		r.Commands.Episode = fmt.Sprintf("logira episode %s --exec-seq %d --json", in.RunID, in.Episode.RootExecSeq)
		for _, ex := range in.Episode.ExecMembers {
			attributed[ex.Event.Seq] = true
		}
		for _, a := range in.Episode.FileEvents {
			attributed[a.Event.Seq] = true
		}
		for _, a := range in.Episode.NetworkEvents {
			attributed[a.Event.Seq] = true
		}
		for _, a := range in.Episode.UncertainEvents {
			uncertain[a.Event.Seq] = true
		}
	}
	var err error
	r.Detections, r.DetectionTotal, r.DetectionOmitted, err = buildDetections(in.Events, attributed, uncertain)
	if err != nil {
		return Report{}, err
	}
	return r, nil
}

func buildRun(in BuildInput) RunOverview {
	command, commandMore := preview(in.Meta.Command, maxDisplayTextBytes)
	argv, argvMore := preview(quoteArgs(in.Meta.CommandArgv), maxDisplayTextBytes)
	state, class := "Finalization unknown", "warning"
	if in.MetadataSource != "missing" {
		if in.Meta.EndTS > 0 {
			state, class = "Finalized retained snapshot", "good"
		} else {
			state = "Provisional snapshot"
		}
	}
	r := RunOverview{
		ID: in.RunID, Mode: "Run Overview", Command: valueOr(command, "unknown"), CommandOmitted: commandMore,
		Argv: valueOr(argv, "unknown"), ArgvOmitted: argvMore, Started: formatTimestamp(in.Meta.StartTS), Ended: formatTimestamp(in.Meta.EndTS),
		Duration: formatDuration(in.Meta.StartTS, in.Meta.EndTS), State: state, StateClass: class,
		Tool: valueOr(in.Meta.Tool, "unknown"), CWD: valueOr(in.Meta.CWD, "unknown"),
		Version: "unknown", EventSource: valueOr(in.EventSource, "unknown"), MetadataSource: valueOr(in.MetadataSource, "missing"),
	}
	if in.Meta.Version != 0 {
		r.Version = strconv.Itoa(in.Meta.Version)
	}
	for _, ev := range in.Events {
		if ev.Seq > r.MaxSeq {
			r.MaxSeq = ev.Seq
		}
		switch ev.Type {
		case storage.TypeExec:
			r.Counts.Exec++
		case storage.TypeProcess:
			r.Counts.Process++
		case storage.TypeFile:
			r.Counts.File++
		case storage.TypeNet:
			r.Counts.Network++
		case storage.TypeDetection:
			r.Counts.Detection++
		default:
			r.Counts.Other++
		}
	}
	r.Counts.Tasks = len(in.Graph.Tasks)
	return r
}

func buildCoverage(c runs.Coverage) []CoverageItem {
	return []CoverageItem{
		coverageItem("Process", c.Process), coverageItem("File", c.File), coverageItem("Network", c.Network),
	}
}

func coverageItem(name string, c runs.KernelCoverage) CoverageItem {
	availability := valueOr(c.Availability, "unknown")
	capture := valueOr(c.Capture, "unknown")
	class := "neutral"
	if capture == "unknown" || capture == "partial" || c.KnownLoss.Total() > 0 {
		class = "warning"
	} else if capture == "complete" {
		class = "good"
	}
	parts := []string{}
	for _, p := range []struct {
		name  string
		value uint64
	}{
		{"shutdown_dropped", c.KnownLoss.ShutdownDropped}, {"collector_forward_dropped", c.KnownLoss.CollectorForwardDropped},
		{"session_queue_dropped", c.KnownLoss.SessionQueueDropped}, {"persistence_failures", c.KnownLoss.PersistenceFailures},
		{"correlation_failures", c.KnownLoss.CorrelationFailures},
	} {
		if p.value > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", p.name, p.value))
		}
	}
	return CoverageItem{Name: name, Availability: availability, Capture: capture, KnownLoss: c.KnownLoss.Total(), LossDetail: strings.Join(parts, ", "), Class: class}
}

func coverageNotes(meta runs.Meta, metadataSource string) []string {
	notes := []string{"Coverage describes retained observations, not proof that all activity was captured. Zero known losses do not prove complete coverage."}
	if metadataSource == "missing" {
		notes = append(notes, "Run metadata is missing; finalization and reported capture state are unknown.")
	}
	if meta.EndTS == 0 {
		notes = append(notes, "This is a provisional snapshot. The Run may still be active or may not have finalized cleanly.")
	}
	if meta.Coverage.DeliveryDrain != "" {
		notes = append(notes, fmt.Sprintf("Delivery drain state: %s; drain failures=%d; finalization failures=%d.", meta.Coverage.DeliveryDrain, meta.Coverage.DrainFailures, meta.Coverage.FinalizationFailures))
	}
	return notes
}

func buildExecRows(g *processgraph.Graph) ([]ExecRow, int, int) {
	seqs := make([]int64, 0, len(g.Execs))
	for seq := range g.Execs {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	total := len(seqs)
	if len(seqs) > maxExecRows {
		seqs = seqs[:maxExecRows]
	}
	rows := make([]ExecRow, 0, len(seqs))
	for _, seq := range seqs {
		rows = append(rows, execRow(*g.Execs[seq], g))
	}
	return rows, total, total - len(rows)
}

func execRow(ex processgraph.Exec, g *processgraph.Graph) ExecRow {
	gen := "unknown"
	if ex.Generation != nil {
		gen = strconv.Itoa(*ex.Generation)
	}
	argv, argvMore := preview(quoteArgs(ex.Detail.Argv), maxDisplayTextBytes)
	raw, rawMore := rawEventPreview(ex.Event)
	ids := "unknown"
	if task := g.Task(ex.TaskID); task != nil {
		ids = formatIdentities(task.Identities)
	}
	return ExecRow{Seq: ex.Event.Seq, Timestamp: formatTimestamp(ex.Event.TS), TaskID: ex.TaskID, Generation: gen,
		Identities: ids, Filename: valueOr(ex.Detail.Filename, "unknown"), Argv: valueOr(argv, "unknown"), ArgvOmitted: argvMore,
		RawJSON: raw, RawOmitted: rawMore}
}

func buildEpisode(ep episode.Episode, g *processgraph.Graph) (EpisodeView, error) {
	v := EpisodeView{Root: execRow(ep.RootExec, g), FileCounts: ep.Summary.File, NetworkCounts: ep.Summary.Network,
		AnalysisSource: ep.AnalysisSource, Limitations: groupIssues(ep.Limitations, "Episode")}
	var err error
	v.Tasks, v.TaskTotal, v.TaskOmitted, v.Relationships = buildTaskRows(ep, g)
	v.File, err = buildFileGroups(ep.FileEvents)
	if err != nil {
		return v, err
	}
	v.Network, err = buildNetworkGroups(ep.NetworkEvents)
	if err != nil {
		return v, err
	}
	v.Uncertain, err = buildUncertainGroups(ep.UncertainEvents)
	if err != nil {
		return v, err
	}
	reasons := make([]string, 0, len(ep.Summary.UnattributableReasons))
	for reason := range ep.Summary.UnattributableReasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)
	for _, reason := range reasons {
		v.Unattributable = append(v.Unattributable, ReasonCount{reason, ep.Summary.UnattributableReasons[reason]})
	}
	return v, nil
}

func buildTaskRows(ep episode.Episode, g *processgraph.Graph) ([]TaskRow, int, int, []RelationshipRow) {
	members := make(map[string]episode.ProcessMember, len(ep.ProcessMembers))
	for _, member := range ep.ProcessMembers {
		members[member.ID] = member
	}
	children := make(map[string][]string)
	confirmedParent := make(map[string]string)
	incoming := make(map[string]processgraph.Fork)
	rels := make([]RelationshipRow, 0, len(ep.Relationships))
	for _, rel := range ep.Relationships {
		parent := "unresolved"
		confirmed := false
		if rel.ParentTaskID != nil {
			parent = *rel.ParentTaskID
		}
		if rel.ParentTaskID != nil && rel.Resolution == "observed_fork" {
			_, parentMember := members[*rel.ParentTaskID]
			_, childMember := members[rel.ChildTaskID]
			if parentMember && childMember {
				children[*rel.ParentTaskID] = append(children[*rel.ParentTaskID], rel.ChildTaskID)
				confirmedParent[rel.ChildTaskID] = *rel.ParentTaskID
				confirmed = true
			}
		}
		incoming[rel.ChildTaskID] = rel
		rels = append(rels, RelationshipRow{rel.Seq, parent, rel.ChildTaskID, valueOr(rel.CloneKind, "unknown"), rel.Resolution, confirmed})
	}
	lessMember := func(a, b string) bool {
		if members[a].EntrySeq != members[b].EntrySeq {
			return members[a].EntrySeq < members[b].EntrySeq
		}
		return a < b
	}
	for id := range children {
		sort.Slice(children[id], func(i, j int) bool { return lessMember(children[id][i], children[id][j]) })
	}
	roots := []string{}
	for id := range members {
		if _, ok := confirmedParent[id]; !ok {
			roots = append(roots, id)
		}
	}
	sort.Slice(roots, func(i, j int) bool { return lessMember(roots[i], roots[j]) })

	fileCount, netCount := map[string]int{}, map[string]int{}
	for _, a := range ep.FileEvents {
		if a.TaskID != nil {
			fileCount[*a.TaskID]++
		}
	}
	for _, a := range ep.NetworkEvents {
		if a.TaskID != nil {
			netCount[*a.TaskID]++
		}
	}
	execs := make(map[string][]processgraph.Exec)
	for _, ex := range ep.ExecMembers {
		execs[ex.TaskID] = append(execs[ex.TaskID], ex)
	}

	type frame struct {
		id    string
		depth int
	}
	stack := make([]frame, 0, len(members))
	for i := len(roots) - 1; i >= 0; i-- {
		stack = append(stack, frame{roots[i], 0})
	}
	seen := map[string]bool{}
	rows := make([]TaskRow, 0, min(len(members), maxTaskRows))
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[cur.id] {
			continue
		}
		seen[cur.id] = true
		if len(rows) < maxTaskRows {
			member := members[cur.id]
			row := TaskRow{Depth: cur.depth, TaskID: cur.id, Entry: fmt.Sprintf("%s:%d", member.EntryKind, member.EntrySeq),
				Identities: formatIdentities(member.Identities), ForkSeqs: formatSeqs(member.ForkSeqs), RekeySeqs: formatSeqs(member.RekeySeqs),
				ExitSeqs: formatSeqs(member.ExitSeqs), ForkOnly: len(member.ExecSeqs) == 0, FileCount: fileCount[cur.id], NetworkCount: netCount[cur.id],
				IdentityConflict: member.Conflicted, GroupDead: valueOr(member.GroupDead, "unknown")}
			visualDepth := min(cur.depth, maxVisualTreeDepth)
			row.Indent = strings.Repeat("│  ", visualDepth)
			if cur.depth > maxVisualTreeDepth {
				row.DepthNote = fmt.Sprintf("actual depth %d", cur.depth)
			}
			if rel, ok := incoming[cur.id]; ok {
				row.CloneKind = valueOr(rel.CloneKind, "unknown")
				row.Relationship = valueOr(rel.Resolution, "unknown")
				if rel.ParentTaskID == nil {
					row.Incoming = "unresolved parent"
				} else if _, ok := members[*rel.ParentTaskID]; !ok {
					row.Incoming = "parent outside selected Episode"
				} else {
					row.Incoming = "confirmed observed fork"
				}
			} else if cur.id == ep.RootExec.TaskID {
				row.Incoming = "selected Episode root"
			} else {
				row.Incoming = "unresolved"
			}
			for _, ex := range execs[cur.id] {
				gen := "unknown"
				if ex.Generation != nil {
					gen = strconv.Itoa(*ex.Generation)
				}
				argv, more := preview(quoteArgs(ex.Detail.Argv), maxDisplayTextBytes)
				row.Execs = append(row.Execs, TaskExec{ex.Event.Seq, gen, valueOr(ex.Detail.Filename, "unknown"), valueOr(argv, "unknown"), more})
			}
			rows = append(rows, row)
		}
		cs := children[cur.id]
		for i := len(cs) - 1; i >= 0; i-- {
			stack = append(stack, frame{cs[i], cur.depth + 1})
		}
	}
	// Defensive: surface any member not reachable through the confirmed forest.
	remaining := []string{}
	for id := range members {
		if !seen[id] {
			remaining = append(remaining, id)
		}
	}
	sort.Slice(remaining, func(i, j int) bool { return lessMember(remaining[i], remaining[j]) })
	for _, id := range remaining {
		if len(rows) >= maxTaskRows {
			break
		}
		member := members[id]
		rows = append(rows, TaskRow{TaskID: id, Entry: fmt.Sprintf("%s:%d", member.EntryKind, member.EntrySeq), Identities: formatIdentities(member.Identities), ForkOnly: len(member.ExecSeqs) == 0, Incoming: "unresolved", GroupDead: valueOr(member.GroupDead, "unknown")})
	}
	sort.Slice(rels, func(i, j int) bool { return rels[i].Seq < rels[j].Seq })
	return rows, len(members), len(members) - len(rows), rels
}

type fileKey struct{ task, exec, attr, op, path, path2, access, syscall, correlation, resolution, ret, bytes string }
type fileAccumulator struct {
	key        fileKey
	count      int
	seqs       []int64
	sourceMore int
	raw        string
	rawMore    int
}

func buildFileGroups(activities []episode.Activity) (ActivitySection[FileGroup], error) {
	section := ActivitySection[FileGroup]{Observed: len(activities)}
	m := map[fileKey]*fileAccumulator{}
	for _, a := range activities {
		var d model.FileDetail
		if err := decodeDetail(a.Event, &d); err != nil {
			return section, err
		}
		ret, bytesValue, err := optionalNumbers(a.Event.DataJSON, "return_value", "bytes")
		if err != nil {
			return section, fmt.Errorf("seq %d (file): %w", a.Event.Seq, err)
		}
		k := fileKey{pointerString(a.TaskID), execRef(a), a.Attribution, valueOr(d.Op, "unknown"), valueOr(d.Path, "unknown"), d.Path2,
			valueOr(d.OpenAccessMode(), "unknown"), valueOr(d.Syscall, "unknown"), valueOr(d.Correlation, "unknown"),
			joinNonEmpty(valueOr(d.PathResolution, "unknown"), valueOr(d.PathResolution2, "")), ret, bytesValue}
		acc := m[k]
		if acc == nil {
			raw, more := rawEventPreview(a.Event)
			acc = &fileAccumulator{key: k, raw: raw, rawMore: more}
			m[k] = acc
		}
		acc.count++
		if len(acc.seqs) < maxSourceSeqsPerGroup {
			acc.seqs = append(acc.seqs, a.Event.Seq)
		} else {
			acc.sourceMore++
		}
	}
	items := make([]*fileAccumulator, 0, len(m))
	for _, v := range m {
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].seqs[0] != items[j].seqs[0] {
			return items[i].seqs[0] < items[j].seqs[0]
		}
		return fmt.Sprint(items[i].key) < fmt.Sprint(items[j].key)
	})
	section.GroupTotal = len(items)
	shown := items
	if len(shown) > maxFileGroups {
		shown = shown[:maxFileGroups]
	}
	for _, a := range shown {
		k := a.key
		section.Groups = append(section.Groups, FileGroup{k.task, k.exec, k.attr, k.op, k.path, k.path2, k.access, k.syscall, k.correlation, k.resolution, k.ret, k.bytes, a.count, formatSeqs(a.seqs), a.sourceMore, a.raw, a.rawMore})
	}
	section.OmittedGroups = len(items) - len(shown)
	for _, a := range items[len(shown):] {
		section.OmittedEvents += a.count
	}
	return section, nil
}

type networkKey struct{ task, exec, attr, op, proto, dst, state, bytes string }
type networkAccumulator struct {
	key        networkKey
	count      int
	seqs       []int64
	sourceMore int
	raw        string
	rawMore    int
}

func buildNetworkGroups(activities []episode.Activity) (ActivitySection[NetworkGroup], error) {
	section := ActivitySection[NetworkGroup]{Observed: len(activities)}
	m := map[networkKey]*networkAccumulator{}
	for _, a := range activities {
		var d model.NetDetail
		if err := decodeDetail(a.Event, &d); err != nil {
			return section, err
		}
		values, _, err := optionalNumbers(a.Event.DataJSON, "bytes", "__unused")
		if err != nil {
			return section, fmt.Errorf("seq %d (net): %w", a.Event.Seq, err)
		}
		dst := valueOr(d.DstIP, "unknown")
		if d.DstPort > 0 {
			dst = fmt.Sprintf("%s:%d", dst, d.DstPort)
		}
		k := networkKey{pointerString(a.TaskID), execRef(a), a.Attribution, valueOr(d.Op, "unknown"), valueOr(d.Proto, "unknown"), dst, valueOr(d.ConnectState, "unknown"), values}
		acc := m[k]
		if acc == nil {
			raw, more := rawEventPreview(a.Event)
			acc = &networkAccumulator{key: k, raw: raw, rawMore: more}
			m[k] = acc
		}
		acc.count++
		if len(acc.seqs) < maxSourceSeqsPerGroup {
			acc.seqs = append(acc.seqs, a.Event.Seq)
		} else {
			acc.sourceMore++
		}
	}
	items := make([]*networkAccumulator, 0, len(m))
	for _, v := range m {
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].seqs[0] != items[j].seqs[0] {
			return items[i].seqs[0] < items[j].seqs[0]
		}
		return fmt.Sprint(items[i].key) < fmt.Sprint(items[j].key)
	})
	section.GroupTotal = len(items)
	shown := items
	if len(shown) > maxNetworkGroups {
		shown = shown[:maxNetworkGroups]
	}
	for _, a := range shown {
		k := a.key
		section.Groups = append(section.Groups, NetworkGroup{k.task, k.exec, k.attr, k.op, k.proto, k.dst, k.state, k.bytes, a.count, formatSeqs(a.seqs), a.sourceMore, a.raw, a.rawMore})
	}
	section.OmittedGroups = len(items) - len(shown)
	for _, a := range items[len(shown):] {
		section.OmittedEvents += a.count
	}
	return section, nil
}

type uncertainKey struct{ typ, basis, reason, task, summary string }
type uncertainAccumulator struct {
	key        uncertainKey
	count      int
	seqs       []int64
	sourceMore int
	raw        string
	rawMore    int
}

func buildUncertainGroups(activities []episode.Activity) (ActivitySection[UncertainGroup], error) {
	section := ActivitySection[UncertainGroup]{Observed: len(activities)}
	m := map[uncertainKey]*uncertainAccumulator{}
	for _, a := range activities {
		summary, err := activitySummary(a.Event)
		if err != nil {
			return section, err
		}
		k := uncertainKey{string(a.Event.Type), valueOr(a.Basis, "unknown"), valueOr(a.Reason, "unknown"), pointerString(a.TaskID), summary}
		acc := m[k]
		if acc == nil {
			raw, more := rawEventPreview(a.Event)
			acc = &uncertainAccumulator{key: k, raw: raw, rawMore: more}
			m[k] = acc
		}
		acc.count++
		if len(acc.seqs) < maxSourceSeqsPerGroup {
			acc.seqs = append(acc.seqs, a.Event.Seq)
		} else {
			acc.sourceMore++
		}
	}
	items := make([]*uncertainAccumulator, 0, len(m))
	for _, v := range m {
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].seqs[0] < items[j].seqs[0] })
	section.GroupTotal = len(items)
	shown := items
	if len(shown) > maxUncertainGroups {
		shown = shown[:maxUncertainGroups]
	}
	for _, a := range shown {
		k := a.key
		section.Groups = append(section.Groups, UncertainGroup{k.typ, k.basis, k.reason, k.task, k.summary, a.count, formatSeqs(a.seqs), a.sourceMore, a.raw, a.rawMore})
	}
	section.OmittedGroups = len(items) - len(shown)
	for _, a := range items[len(shown):] {
		section.OmittedEvents += a.count
	}
	return section, nil
}

func activitySummary(ev storage.Event) (string, error) {
	switch ev.Type {
	case storage.TypeFile:
		var d model.FileDetail
		if err := decodeDetail(ev, &d); err != nil {
			return "", err
		}
		return fmt.Sprintf("op=%s path=%s path2=%s syscall=%s correlation=%s resolution=%s/%s", valueOr(d.Op, "unknown"), valueOr(d.Path, "unknown"), valueOr(d.Path2, "—"), valueOr(d.Syscall, "unknown"), valueOr(d.Correlation, "unknown"), valueOr(d.PathResolution, "unknown"), valueOr(d.PathResolution2, "unknown")), nil
	case storage.TypeNet:
		var d model.NetDetail
		if err := decodeDetail(ev, &d); err != nil {
			return "", err
		}
		return fmt.Sprintf("op=%s proto=%s destination=%s:%d state=%s bytes=%d", valueOr(d.Op, "unknown"), valueOr(d.Proto, "unknown"), valueOr(d.DstIP, "unknown"), d.DstPort, valueOr(d.ConnectState, "unknown"), d.Bytes), nil
	default:
		return valueOr(ev.Summary, "unknown"), nil
	}
}

func buildDetections(events []storage.Event, attributed, uncertain map[int64]bool) ([]DetectionGroup, int, int, error) {
	type detectionRecord struct {
		event  storage.Event
		detail storage.Detection
	}
	type key struct{ severity, rule, message string }
	groups := map[key][]detectionRecord{}
	bySeq := map[int64]storage.Event{}
	total := 0
	for _, ev := range events {
		bySeq[ev.Seq] = ev
	}
	for _, ev := range events {
		if ev.Type != storage.TypeDetection {
			continue
		}
		var d storage.Detection
		if err := decodeDetail(ev, &d); err != nil {
			return nil, 0, 0, err
		}
		k := key{strings.ToLower(valueOr(d.Severity, "unknown")), d.RuleID, d.Message}
		groups[k] = append(groups[k], detectionRecord{ev, d})
		total++
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		wi, wj := severityWeight(keys[i].severity), severityWeight(keys[j].severity)
		if wi != wj {
			return wi > wj
		}
		if keys[i].rule != keys[j].rule {
			return keys[i].rule < keys[j].rule
		}
		return keys[i].message < keys[j].message
	})
	omitted := 0
	if len(keys) > maxDetectionGroups {
		omitted = len(keys) - maxDetectionGroups
		keys = keys[:maxDetectionGroups]
	}
	out := make([]DetectionGroup, 0, len(keys))
	for _, k := range keys {
		records := groups[k]
		sort.Slice(records, func(i, j int) bool { return records[i].event.Seq < records[j].event.Seq })
		g := DetectionGroup{Severity: strings.ToUpper(k.severity), SeverityClass: severityClass(k.severity), RuleID: valueOr(k.rule, "unknown"), Message: valueOr(k.message, "unknown"), Count: len(records), First: formatTimestamp(records[0].event.TS), Last: formatTimestamp(records[len(records)-1].event.TS)}
		for _, rec := range records[:min(len(records), maxDetectionEvidence)] {
			related, state, typ, summary := rec.detail.RelatedEventSeq, "No related event reference", "—", "—"
			if related > 0 {
				if ev, ok := bySeq[related]; ok {
					typ = string(ev.Type)
					summary = valueOr(ev.Summary, "(no summary)")
					switch {
					case attributed[related]:
						state = "References attributed Episode evidence"
					case uncertain[related]:
						state = "References uncertain candidate evidence"
					default:
						state = "Run-scoped retained evidence"
					}
				} else {
					state = "Related event unavailable"
				}
			}
			raw, more := rawEventPreview(rec.event)
			g.Evidence = append(g.Evidence, DetectionEvidence{rec.event.Seq, related, typ, state, summary, raw, more})
		}
		g.EvidenceMore = len(records) - len(g.Evidence)
		out = append(out, g)
	}
	return out, total, omitted, nil
}

func groupIssues(issues []processgraph.Issue, scope string) []IssueGroup {
	type acc struct {
		count int
		refs  []string
		more  int
	}
	m := map[string]*acc{}
	for _, issue := range issues {
		a := m[issue.Code]
		if a == nil {
			a = &acc{}
			m[issue.Code] = a
		}
		a.count++
		ref := ""
		if issue.TaskID != "" {
			ref = issue.TaskID
		}
		if issue.Seq > 0 {
			if ref != "" {
				ref += "/"
			}
			ref += fmt.Sprintf("seq=%d", issue.Seq)
		}
		if ref != "" {
			if len(a.refs) < maxSourceSeqsPerGroup {
				a.refs = append(a.refs, ref)
			} else {
				a.more++
			}
		}
	}
	codes := make([]string, 0, len(m))
	for code := range m {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	out := make([]IssueGroup, 0, len(codes))
	for _, code := range codes {
		a := m[code]
		out = append(out, IssueGroup{code, issueMessage(code), a.count, strings.Join(a.refs, ", "), a.more, scope})
	}
	return out
}

func issueMessage(code string) string {
	switch code {
	case "missing_fork":
		return "No retained fork observation identifies this task's parent."
	case "missing_exit":
		return "No retained exit observation closes this task lifetime."
	case "unresolved_parent":
		return "A retained fork did not resolve to one confirmed parent task."
	case "ancestry_cycle":
		return "Cyclic fork evidence was excluded from confirmed ancestry."
	case "uncertain_descendant_membership", "uncertain_exec_membership":
		return "Available ordering or identity evidence cannot confirm Episode membership."
	case "uncertain_path_resolution":
		return "At least one path remains unresolved or best-effort."
	case "incomplete_file_correlation":
		return "A file syscall observation has incomplete enter/exit correlation."
	case "run_not_finalized":
		return "The analyzed Run is a provisional snapshot."
	case "missing_run_metadata":
		return "Run metadata is missing."
	default:
		return strings.ReplaceAll(code, "_", " ") + "."
	}
}

func decodeDetail(ev storage.Event, target any) error {
	b := bytes.TrimSpace(ev.DataJSON)
	if len(b) == 0 || b[0] != '{' {
		return fmt.Errorf("seq %d (%s): data_json must be an object", ev.Seq, ev.Type)
	}
	if err := json.Unmarshal(ev.DataJSON, target); err != nil {
		return fmt.Errorf("seq %d (%s): %w", ev.Seq, ev.Type, err)
	}
	return nil
}

func optionalNumbers(raw json.RawMessage, first, second string) (string, string, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", "", err
	}
	value := func(name string) string {
		b, ok := m[name]
		if !ok {
			return "unknown"
		}
		return string(b)
	}
	return value(first), value(second), nil
}

func rawEventPreview(ev storage.Event) (string, int) {
	b, err := json.MarshalIndent(ev, "", "  ")
	if err != nil {
		return fmt.Sprintf("unable to format event: %v", err), 0
	}
	return preview(string(b), maxRawPreviewBytes)
}

func preview(value string, limit int) (string, int) {
	if len(value) <= limit {
		return value, 0
	}
	cut := limit
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut], len(value) - cut
}

func quoteArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	out := make([]string, len(args))
	for i, arg := range args {
		out[i] = strconv.Quote(arg)
	}
	return strings.Join(out, " ")
}
func valueOr(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}
func pointerString(v *string) string {
	if v == nil || *v == "" {
		return "unknown"
	}
	return *v
}
func execRef(a episode.Activity) string {
	if a.ExecSeq == nil {
		return "unknown"
	}
	gen := "unknown"
	if a.Generation != nil {
		gen = strconv.Itoa(*a.Generation)
	}
	return fmt.Sprintf("seq=%d generation=%s", *a.ExecSeq, gen)
}
func formatSeqs[T ~int64](seqs []T) string {
	if len(seqs) == 0 {
		return "—"
	}
	parts := make([]string, len(seqs))
	for i, s := range seqs {
		parts[i] = strconv.FormatInt(int64(s), 10)
	}
	return strings.Join(parts, ", ")
}
func formatIdentities(ids []processgraph.Identity) string {
	if len(ids) == 0 {
		return "unknown"
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		p := fmt.Sprintf("tid=%d tgid=%d", id.TID, id.TGID)
		if id.Birth > 0 {
			p += fmt.Sprintf(" birth=%d", id.Birth)
		} else if id.FirstObserved > 0 {
			p += fmt.Sprintf(" first=%d", id.FirstObserved)
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}
func joinNonEmpty(a, b string) string {
	if strings.TrimSpace(b) == "" {
		return a
	}
	return a + " / " + b
}
func formatTimestamp(ns int64) string {
	if ns <= 0 {
		return "unknown"
	}
	return time.Unix(0, ns).UTC().Format("2006-01-02 15:04:05.000 UTC")
}
func formatDuration(start, end int64) string {
	if start <= 0 || end <= 0 || end < start {
		return "unknown"
	}
	d := time.Duration(end - start)
	if d < time.Millisecond {
		return d.String()
	}
	return d.Round(time.Millisecond).String()
}
func severityWeight(v string) int {
	switch strings.ToLower(v) {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
func severityClass(v string) string {
	switch strings.ToLower(v) {
	case "high":
		return "severity-high"
	case "medium":
		return "severity-medium"
	case "low":
		return "severity-low"
	case "info":
		return "severity-info"
	default:
		return "neutral"
	}
}
