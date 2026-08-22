package residual

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/runs"
	"github.com/melonattacker/logira/internal/storage"
)

// ExecMemberRole describes only the structural relationship between an exec
// observation and the direct match. It does not express expectedness, safety,
// or semantic legitimacy.
type ExecMemberRole string

const (
	ExecRoleDirectMatch     ExecMemberRole = "direct_match"
	ExecRoleWrapper         ExecMemberRole = "wrapper"
	ExecRoleExecReplacement ExecMemberRole = "exec_replacement"
	ExecRoleDescendant      ExecMemberRole = "descendant"
	ExecRoleUnknown         ExecMemberRole = "unknown"
)

type ExecMember struct {
	Seq           int64          `json:"seq"`
	TS            int64          `json:"ts"`
	PID           int            `json:"pid"`
	PPID          int            `json:"ppid,omitempty"`
	Generation    int            `json:"generation"`
	ParentExecSeq int64          `json:"parent_exec_seq,omitempty"`
	Role          ExecMemberRole `json:"role"`
	Summary       string         `json:"summary"`
	Filename      string         `json:"filename,omitempty"`
	Argv          []string       `json:"argv,omitempty"`
	CWD           string         `json:"cwd,omitempty"`
}

// ProcessMember is a kernel task instance. It may have no exec observation;
// in that case no synthetic exec sequence or generation is assigned.
type ProcessMember struct {
	TID                     int    `json:"tid"`
	TGID                    int    `json:"tgid,omitempty"`
	TaskStartKernelNS       uint64 `json:"task_start_kernel_ns,omitempty"`
	ParentTID               int    `json:"parent_tid,omitempty"`
	ParentTGID              int    `json:"parent_tgid,omitempty"`
	ParentTaskStartKernelNS uint64 `json:"parent_task_start_kernel_ns,omitempty"`
	ForkSeq                 int64  `json:"fork_seq,omitempty"`
	ExitSeq                 int64  `json:"exit_seq,omitempty"`
	CloneKind               string `json:"clone_kind"`
	GroupDead               string `json:"group_dead"`
}

type FileEffect struct {
	Seq               int64  `json:"seq"`
	TS                int64  `json:"ts"`
	PID               int    `json:"pid"`
	ProcessExecSeq    int64  `json:"process_exec_seq,omitempty"`
	ProcessGeneration int    `json:"process_generation,omitempty"`
	Attribution       string `json:"attribution"`
	Op                string `json:"op"`
	Path              string `json:"path"`
	Summary           string `json:"summary"`
}

type NetworkEffect struct {
	Seq               int64  `json:"seq"`
	TS                int64  `json:"ts"`
	PID               int    `json:"pid"`
	ProcessExecSeq    int64  `json:"process_exec_seq,omitempty"`
	ProcessGeneration int    `json:"process_generation,omitempty"`
	Attribution       string `json:"attribution"`
	Op                string `json:"op"`
	Proto             string `json:"proto,omitempty"`
	DstIP             string `json:"dst_ip,omitempty"`
	DstPort           uint16 `json:"dst_port,omitempty"`
	Bytes             int64  `json:"bytes,omitempty"`
	Summary           string `json:"summary"`
}

type EpisodeSummary struct {
	Execs           int `json:"execs"`
	Wrappers        int `json:"wrappers"`
	TransitiveExecs int `json:"transitive_execs"`
	Files           int `json:"files"`
	Networks        int `json:"networks"`
	Processes       int `json:"processes"`
}

// ExecutionEpisode is an observed causal envelope around one matched runtime
// action. Membership does not assert that an effect was semantically justified.
type ExecutionEpisode struct {
	ActionID          string          `json:"action_id"`
	ItemID            string          `json:"item_id,omitempty"`
	Command           string          `json:"command"`
	AgentSeq          int64           `json:"agent_seq"`
	ActionStartTS     int64           `json:"action_start_ts"`
	ActionEndTS       int64           `json:"action_end_ts"`
	Confidence        string          `json:"confidence"`
	DirectMatch       ExecMember      `json:"direct_match"`
	ExecMembers       []ExecMember    `json:"exec_members"`
	ProcessMembers    []ProcessMember `json:"process_members,omitempty"`
	FileEffects       []FileEffect    `json:"file_effects,omitempty"`
	NetworkEffects    []NetworkEffect `json:"network_effects,omitempty"`
	Summary           EpisodeSummary  `json:"summary"`
	ProcessCapture    string          `json:"process_capture"`
	FileCapture       string          `json:"file_capture"`
	NetworkCapture    string          `json:"network_capture"`
	FileEffectScope   string          `json:"file_effect_scope"`
	AncestryComplete  bool            `json:"ancestry_complete"`
	AttributionIssues []string        `json:"attribution_issues,omitempty"`
}

func buildExecutionEpisode(meta runs.Meta, action commandAction, anchor int, confidence string, execs []execEvent, members map[int]bool, events []storage.Event, processes *processGraph) ExecutionEpisode {
	actionID := action.itemID
	if actionID == "" {
		actionID = fmt.Sprintf("agent-seq:%d", action.seq)
	}
	episode := ExecutionEpisode{
		ActionID:         actionID,
		ItemID:           action.itemID,
		Command:          action.command,
		AgentSeq:         action.seq,
		ActionStartTS:    action.start,
		ActionEndTS:      action.end,
		Confidence:       confidence,
		ProcessCapture:   meta.Coverage.Process.Capture,
		FileCapture:      meta.Coverage.File.Capture,
		NetworkCapture:   meta.Coverage.Network.Capture,
		FileEffectScope:  "retained_events",
		AncestryComplete: true,
	}

	indexes := make([]int, 0, len(members))
	for i := range members {
		indexes = append(indexes, i)
	}
	sort.Slice(indexes, func(i, j int) bool {
		left, right := execs[indexes[i]].ev, execs[indexes[j]].ev
		if left.TS == right.TS {
			return left.Seq < right.Seq
		}
		return left.TS < right.TS
	})

	for _, i := range indexes {
		ex := execs[i]
		member := ExecMember{
			Seq:        ex.ev.Seq,
			TS:         ex.ev.TS,
			PID:        ex.ev.PID,
			PPID:       ex.ev.PPID,
			Generation: ex.generation,
			Role:       episodeExecRole(i, anchor, execs, members),
			Summary:    ex.ev.Summary,
			Filename:   ex.detail.Filename,
			Argv:       append([]string(nil), ex.detail.Argv...),
			CWD:        ex.detail.CWD,
		}
		if ex.parent >= 0 && members[ex.parent] {
			member.ParentExecSeq = execs[ex.parent].ev.Seq
		}
		if i == anchor {
			episode.DirectMatch = member
		}
		episode.ExecMembers = append(episode.ExecMembers, member)
	}

	for _, i := range indexes {
		ex := execs[i]
		if ex.parent >= 0 || ex.ev.PPID <= 0 {
			continue
		}
		episode.AncestryComplete = false
		if i == anchor {
			episode.AttributionIssues = append(episode.AttributionIssues, "direct match parent exec was not observed")
		} else {
			episode.AttributionIssues = append(episode.AttributionIssues, fmt.Sprintf("episode member parent exec was not observed (seq=%d)", ex.ev.Seq))
		}
	}
	if meta.Coverage.Process.Capture != "complete" {
		episode.AttributionIssues = append(episode.AttributionIssues, "process capture is not complete; episode membership may be incomplete")
	}
	if meta.Coverage.File.Capture != "complete" {
		episode.AttributionIssues = append(episode.AttributionIssues, "file capture is not complete; attributed file effects may be incomplete")
	}
	if meta.Coverage.Network.Capture != "complete" {
		episode.AttributionIssues = append(episode.AttributionIssues, "network capture is not complete; attributed network effects may be incomplete")
	}

	processMembers, processTasks := processes.episodeProcessMembers(execs, members, action)
	episode.ProcessMembers = processMembers
	attachEpisodeEffects(&episode, action, execs, members, processTasks, events, processes)
	wrappers, transitive := 0, 0
	for _, member := range episode.ExecMembers {
		switch member.Role {
		case ExecRoleWrapper:
			wrappers++
		case ExecRoleDirectMatch:
		default:
			transitive++
		}
	}
	episode.Summary = EpisodeSummary{
		Execs:           len(episode.ExecMembers),
		Wrappers:        wrappers,
		TransitiveExecs: transitive,
		Files:           len(episode.FileEffects),
		Networks:        len(episode.NetworkEffects),
		Processes:       len(episode.ProcessMembers),
	}
	return episode
}

func episodeExecRole(index, anchor int, execs []execEvent, members map[int]bool) ExecMemberRole {
	if index == anchor {
		return ExecRoleDirectMatch
	}
	if isAncestorExec(index, anchor, execs, members) && isExecutionWrapper(execs[index].detail) {
		return ExecRoleWrapper
	}
	parent := execs[index].parent
	if parent >= 0 && members[parent] {
		if execs[parent].ev.PID == execs[index].ev.PID {
			return ExecRoleExecReplacement
		}
		return ExecRoleDescendant
	}
	return ExecRoleUnknown
}

func isAncestorExec(candidate, child int, execs []execEvent, members map[int]bool) bool {
	seen := make(map[int]bool)
	for parent := execs[child].parent; parent >= 0 && members[parent] && !seen[parent]; parent = execs[parent].parent {
		if parent == candidate {
			return true
		}
		seen[parent] = true
	}
	return false
}

func attachEpisodeEffects(episode *ExecutionEpisode, action commandAction, execs []execEvent, members map[int]bool, processTasks map[taskIdentity]bool, events []storage.Event, processes *processGraph) {
	const skew = int64(5_000_000_000)
	windowStart, windowEnd := action.start-skew, action.end+skew
	for _, ev := range events {
		if ev.TS < windowStart || ev.TS > windowEnd || (ev.Type != storage.TypeFile && ev.Type != storage.TypeNet) {
			continue
		}
		pid := ev.PID
		var identity taskIdentity
		var kernelNS uint64
		var fileDetail model.FileDetail
		var netDetail model.NetDetail
		switch ev.Type {
		case storage.TypeFile:
			if json.Unmarshal(ev.DataJSON, &fileDetail) != nil {
				continue
			}
			if pid == 0 {
				pid = fileDetail.PID
			}
			identity = taskIdentity{tid: fileDetail.TID, start: fileDetail.TaskStartKernelNS}
			kernelNS = fileDetail.KernelTimeNS
		case storage.TypeNet:
			if json.Unmarshal(ev.DataJSON, &netDetail) != nil {
				continue
			}
			identity = taskIdentity{tid: netDetail.TID, start: netDetail.TaskStartKernelNS}
			kernelNS = netDetail.KernelTimeNS
		}
		if pid <= 0 {
			continue
		}
		if identity.tid <= 0 {
			identity.tid = pid
		}
		if identity.start == 0 {
			if fork := processes.forkForChild(identity, kernelNS); fork != nil {
				identity.start = fork.child.start
			}
		}
		execIndex := latestExecGeneration(execs, identity, ev.TS, ev.Seq, kernelNS)
		if execIndex >= 0 && !members[execIndex] {
			execIndex = -1
		}
		if execIndex < 0 && !processTasks[identity] {
			continue
		}
		processExecSeq, processGeneration, attribution := int64(0), 0, "task_instance_no_exec"
		if execIndex >= 0 {
			processExecSeq = execs[execIndex].ev.Seq
			processGeneration = execs[execIndex].generation
			attribution = "task_instance_latest_exec_generation"
		}
		switch ev.Type {
		case storage.TypeFile:
			episode.FileEffects = append(episode.FileEffects, FileEffect{
				Seq: ev.Seq, TS: ev.TS, PID: pid, ProcessExecSeq: processExecSeq,
				ProcessGeneration: processGeneration, Attribution: attribution,
				Op: strings.TrimSpace(fileDetail.Op), Path: fileDetail.Path, Summary: ev.Summary,
			})
		case storage.TypeNet:
			episode.NetworkEffects = append(episode.NetworkEffects, NetworkEffect{
				Seq: ev.Seq, TS: ev.TS, PID: pid, ProcessExecSeq: processExecSeq,
				ProcessGeneration: processGeneration, Attribution: attribution,
				Op: strings.TrimSpace(netDetail.Op), Proto: netDetail.Proto, DstIP: netDetail.DstIP,
				DstPort: netDetail.DstPort, Bytes: netDetail.Bytes, Summary: ev.Summary,
			})
		}
	}
}

func latestExecGeneration(execs []execEvent, identity taskIdentity, ts, seq int64, kernelNS uint64) int {
	latest := -1
	for i, ex := range execs {
		if ex.ev.TS > ts || (ex.ev.TS == ts && ex.ev.Seq > seq) {
			break
		}
		if ex.identity == identity || (identity.start == 0 && ex.identity.tid == identity.tid) {
			if kernelNS != 0 && ex.detail.KernelTimeNS != 0 && ex.detail.KernelTimeNS > kernelNS {
				continue
			}
			latest = i
		}
	}
	return latest
}
