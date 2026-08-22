package residual

import (
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

func TestObservedScenarioEpisodesPreserveResidualClassifications(t *testing.T) {
	tests := []struct {
		name             string
		command          string
		direct           model.ExecDetail
		transitive       []scenarioExec
		wantExecs        int
		wantTransitive   int
		wantVisibleToken string
	}{
		{
			name: "baseline", command: `bash -c 'printf BASELINE'`,
			direct:    model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "printf BASELINE"}},
			wantExecs: 1, wantTransitive: 0,
		},
		{
			name: "go process tree", command: `bash -c 'go test ./...'`,
			direct:     model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "go test ./..."}},
			transitive: goScenarioExecs(), wantExecs: 19, wantTransitive: 18, wantVisibleToken: "calc.test",
		},
		{
			name: "path hijack", command: `bash -c 'git status'`,
			direct: model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "git status"}},
			transitive: []scenarioExec{
				{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/tmp/bin/git", Argv: []string{"git", "status"}}},
				{pid: 21, ppid: 20, detail: model.ExecDetail{Filename: "/usr/bin/touch", Argv: []string{"touch", "/tmp/path-marker"}}},
				{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"/usr/bin/git", "status"}}},
			},
			wantExecs: 4, wantTransitive: 3, wantVisibleToken: "path-marker",
		},
		{
			name: "make side effect", command: `bash -c 'make test'`,
			direct: model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "make test"}},
			transitive: []scenarioExec{
				{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/usr/bin/make", Argv: []string{"make", "test"}}},
				{pid: 21, ppid: 20, detail: model.ExecDetail{Filename: "/usr/bin/touch", Argv: []string{"touch", "/tmp/build-marker"}}},
			},
			wantExecs: 3, wantTransitive: 2, wantVisibleToken: "build-marker",
		},
		{
			name: "git hook", command: `bash -c 'git commit -m hook'`,
			direct: model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "git commit -m hook"}},
			transitive: []scenarioExec{
				{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/usr/bin/git", Argv: []string{"git", "commit", "-m", "hook"}}},
				{pid: 21, ppid: 20, detail: model.ExecDetail{Filename: ".git/hooks/post-commit", Argv: []string{".git/hooks/post-commit"}}},
				{pid: 22, ppid: 21, detail: model.ExecDetail{Filename: "/usr/bin/touch", Argv: []string{"touch", "/tmp/hook-marker"}}},
			},
			wantExecs: 4, wantTransitive: 3, wantVisibleToken: "hook-marker",
		},
		{
			name: "shell startup", command: `bash -c 'bash --rcfile ./scenario.bashrc -i -c true'`,
			direct: model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "-c", "bash --rcfile ./scenario.bashrc -i -c true"}},
			transitive: []scenarioExec{
				{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/bin/bash", Argv: []string{"bash", "--rcfile", "./scenario.bashrc", "-i", "-c", "true"}}},
				{pid: 21, ppid: 20, detail: model.ExecDetail{Filename: "/usr/bin/touch", Argv: []string{"touch", "/tmp/startup-marker"}}},
			},
			wantExecs: 3, wantTransitive: 2, wantVisibleToken: "startup-marker",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			report := Analyze(completeMeta(), scenarioEvents(tc.command, tc.direct, tc.transitive))
			if report.Counts[Matched] != 1 || report.Counts[ReportedNotObserved] != 0 || report.Counts[ObservedNotReported] != 0 || report.Counts[Blocked] != 0 || report.Counts[Unobservable] != 0 {
				t.Fatalf("classifications changed: %+v", report.Counts)
			}
			if len(report.Episodes) != 1 {
				t.Fatalf("episodes=%+v", report.Episodes)
			}
			episode := report.Episodes[0]
			if episode.Summary.Execs != tc.wantExecs || episode.Summary.TransitiveExecs != tc.wantTransitive {
				t.Fatalf("summary=%+v", episode.Summary)
			}
			if tc.wantVisibleToken != "" && !episodeContainsArg(episode, tc.wantVisibleToken) {
				t.Fatalf("episode does not expose %q: %+v", tc.wantVisibleToken, episode.ExecMembers)
			}
		})
	}
}

type scenarioExec struct {
	pid, ppid int
	detail    model.ExecDetail
}

func scenarioEvents(command string, direct model.ExecDetail, transitive []scenarioExec) []storage.Event {
	events := []storage.Event{
		{RunID: "r", Seq: 1, TS: 1, Type: storage.TypeExec, PID: 10, PPID: 1, Summary: "exec codex", DataJSON: mustJSON(model.ExecDetail{Filename: "/usr/bin/codex"})},
		event(2, 2, storage.TypeAgent, model.AgentDetail{Kind: "turn_started"}),
		event(3, 10, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "in_progress"}),
		{RunID: "r", Seq: 4, TS: 11, Type: storage.TypeExec, PID: 20, PPID: 10, Summary: "exec " + joinArgv(direct.Argv), DataJSON: mustJSON(direct)},
	}
	seq, ts := int64(5), int64(12)
	for _, ex := range transitive {
		events = append(events, storage.Event{RunID: "r", Seq: seq, TS: ts, Type: storage.TypeExec, PID: ex.pid, PPID: ex.ppid, Summary: "exec " + joinArgv(ex.detail.Argv), DataJSON: mustJSON(ex.detail)})
		seq++
		ts++
	}
	events = append(events, event(seq, ts, storage.TypeAgent, model.AgentDetail{Kind: "command_execution", ItemID: "item_1", Command: command, Status: "completed"}))
	return events
}

func goScenarioExecs() []scenarioExec {
	out := []scenarioExec{{pid: 20, ppid: 10, detail: model.ExecDetail{Filename: "/usr/bin/go", Argv: []string{"go", "test", "./..."}}}}
	for i := 0; i < 16; i++ {
		out = append(out, scenarioExec{pid: 30 + i, ppid: 20, detail: model.ExecDetail{Filename: "/usr/lib/go/pkg/tool/compile", Argv: []string{"compile", "-V=full"}}})
	}
	out = append(out, scenarioExec{pid: 50, ppid: 20, detail: model.ExecDetail{Filename: "/tmp/build/calc.test", Argv: []string{"/tmp/build/calc.test"}}})
	return out
}

func joinArgv(argv []string) string {
	out := ""
	for i, arg := range argv {
		if i > 0 {
			out += " "
		}
		out += arg
	}
	return out
}

func episodeContainsArg(episode ExecutionEpisode, token string) bool {
	for _, member := range episode.ExecMembers {
		for _, arg := range member.Argv {
			if strings.Contains(arg, token) {
				return true
			}
		}
	}
	return false
}
