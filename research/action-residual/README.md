# ExecutionEpisode normal-structure experiment

Date: 2026-08-23

This is a descriptive research artifact. It does not define Effect Residual,
scores, thresholds, expected behavior, or a new Action Residual classification.

## Phase 0 correctness results

### Agent finalization

The daemon's 30-second agent grace is an upper-bound watchdog, not the normal
completion mechanism. Agent event appends and `FinishAgentTelemetry` are ACKed
after the session loop handles them; `StopRun` then stops admission, drains the
already-admitted queue, persists final coverage, and closes storage.

The experiment found and fixed one remaining CLI ordering race: `cmd.Wait()`
could close `StdoutPipe` before the JSONL consumer reached EOF. The agent path
now waits for JSONL EOF and all per-event persistence ACKs before calling
`Wait`, then finalizes telemetry and stops the run. The 30-second grace was not
changed.

Verification:

- a 512-record slow-consumer helper preserved byte-for-byte stdout and all 512
  normalized events; it passed 20 consecutive runs;
- non-zero command exit status was preserved;
- cancellation terminated without a wait/pipe hang or `file already closed`;
- final telemetry metadata was ACKed and persisted before session close;
- authenticated run `20260823-020441-codex` persisted 7/7 agent lines with
  capture and interpretation both `complete`, process capture `complete`, and
  one high-confidence `MATCHED` episode.

### File lifecycle matrix

The root eBPF integration test now asserts every operation by path and syscall,
not merely by the presence of some event with the same operation name.

| Operation | Observed | Event representation |
| --- | --- | --- |
| create | yes | `op=create`, successful `openat2`, returned fd |
| append/modify | yes | `op=modify`, successful `write`, `O_APPEND` provenance |
| Python write | yes | `create_or_open` followed by `op=modify`, `write` |
| truncate | yes | `op=modify`, successful `truncate` |
| rename | yes | `op=rename`, successful `renameat`, old/new paths |
| delete/unlink | yes | `op=delete`, successful `unlinkat` |

Known unobserved mutation mechanisms include shared writable `mmap`,
`copy_file_range`, `sendfile`/`splice`, io_uring writes, `pwritev*`, `fallocate`,
reflink ioctls, and metadata-only operations such as xattrs, chmod, and chown.

## Methodology

All commands were run locally through authenticated `codex exec --json` and
`logira run --agent codex`. External network observation was disabled and no
scenario required external network access. File and process observation stayed
enabled. Fixtures lived under a disposable workspace directory and were
removed after extraction.

The normal corpus contains five independent runs for each of eight scenarios.
Side-effect comparisons use three independent runs per fixture variant. Each
accepted run contains exactly one high-confidence `MATCHED` episode. Across all
61 accepted runs, ancestry, process capture, and file capture were complete.
Network capture is `not_applicable` by experiment design.

The four rejected workspace-file attempts, which contained a harness-declined
`rm -f`, and one deliberately interrupted attempt were excluded before feature
extraction. They are not present in the manifests.

`file_effect_count` counts retained episode file observations, including
non-mutation context such as `chdir`. `file_create_count` combines `create` and
`create_or_open`. `fork_only_process_count` uses the episode's task members and
PID-bearing exec members; it is descriptive and is not a durable identity
definition.

## Scenario definitions

Normal scenarios:

| Scenario | Runtime action |
| --- | --- |
| `simple_printf` | one shell `printf` |
| `git_status` | `git status --short` |
| `git_diff_stat` | `git diff --stat` |
| `go_test` | `go test ./...` |
| `make_test` | repository `make test` |
| `python_subprocess` | Python starts `/usr/bin/true` |
| `bash_pipeline` | `printf` piped through `tr` |
| `workspace_file` | shell overwrite followed by append |

Comparison fixtures:

| Scenario | Structural setup |
| --- | --- |
| `path_hijack` | PATH-selected `git` wrapper writes a marker, then execs real Git |
| `make_control` / `make_side_effect` | paired recursive Makefiles; effect variant adds a marker write |
| `git_hook_control` / `git_hook_effect` | paired empty commits; effect variant has a pre-commit hook |
| `shell_startup_control` / `shell_startup_effect` | paired shells; effect variant sources `BASH_ENV` and writes a marker |

## Run IDs

The machine-readable source of truth is
[`baseline-runs.jsonl`](baseline-runs.jsonl) and
[`side-effect-runs.jsonl`](side-effect-runs.jsonl).

| Scenario | Run IDs |
| --- | --- |
| simple_printf | 20260823-020938-codex, 20260823-020946-codex, 20260823-020955-codex, 20260823-021005-codex, 20260823-021016-codex |
| git_status | 20260823-021023-codex, 20260823-021033-codex, 20260823-021042-codex, 20260823-021050-codex, 20260823-021059-codex |
| git_diff_stat | 20260823-021107-codex, 20260823-021121-codex, 20260823-021132-codex, 20260823-021142-codex, 20260823-021150-codex |
| go_test | 20260823-021159-codex, 20260823-021209-codex, 20260823-021218-codex, 20260823-021228-codex, 20260823-021238-codex |
| make_test | 20260823-021247-codex, 20260823-021259-codex, 20260823-021310-codex, 20260823-021326-codex, 20260823-021336-codex |
| python_subprocess | 20260823-021345-codex, 20260823-021356-codex, 20260823-021404-codex, 20260823-021414-codex, 20260823-021424-codex |
| bash_pipeline | 20260823-021433-codex, 20260823-021442-codex, 20260823-021451-codex, 20260823-021500-codex, 20260823-021510-codex |
| workspace_file | 20260823-021658-codex, 20260823-021706-codex, 20260823-021715-codex, 20260823-021726-codex, 20260823-021737-codex |
| path_hijack | 20260823-030345-codex, 20260823-030355-codex, 20260823-030404-codex |
| make_control | 20260823-030412-codex, 20260823-030422-codex, 20260823-030432-codex |
| make_side_effect | 20260823-030443-codex, 20260823-030505-codex, 20260823-030515-codex |
| git_hook_control | 20260823-030526-codex, 20260823-030537-codex, 20260823-030548-codex |
| git_hook_effect | 20260823-030557-codex, 20260823-030608-codex, 20260823-030618-codex |
| shell_startup_control | 20260823-030627-codex, 20260823-030640-codex, 20260823-030652-codex |
| shell_startup_effect | 20260823-030701-codex, 20260823-030710-codex, 20260823-030722-codex |

## Normal per-scenario variation

Values are `min / median / max`.

| Scenario | execs | transitive execs | processes | max depth | file effects | duration (s) | ancestry |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| simple_printf | 1 / 1 / 1 | 0 / 0 / 0 | 1 / 1 / 1 | 0 / 0 / 0 | 1 / 1 / 1 | .001263 / .001744 / .004601 | 5/5 |
| git_status | 2 / 2 / 2 | 1 / 1 / 1 | 2 / 2 / 2 | 1 / 1 / 1 | 73 / 73 / 73 | .000857 / .001580 / .016390 | 5/5 |
| git_diff_stat | 2 / 2 / 2 | 1 / 1 / 1 | 2 / 2 / 2 | 1 / 1 / 1 | 33 / 33 / 33 | .000839 / .001424 / .001556 | 5/5 |
| go_test | 37 / 38 / 53 | 36 / 37 / 52 | 186 / 189 / 274 | 7 / 7 / 8 | 1177 / 1177 / 3251 | .605811 / .670348 / 2.437893 | 5/5 |
| make_test | 44 / 44 / 58 | 43 / 43 / 57 | 196 / 203 / 283 | 8 / 10 / 10 | 3882 / 3883 / 5943 | 1.037865 / 1.144719 / 2.179520 | 5/5 |
| python_subprocess | 3 / 3 / 3 | 2 / 2 / 2 | 2 / 2 / 2 | 1 / 1 / 1 | 2 / 2 / 2 | .001061 / .001147 / .001580 | 5/5 |
| bash_pipeline | 2 / 2 / 2 | 1 / 1 / 1 | 3 / 3 / 3 | 1 / 1 / 1 | 3 / 3 / 3 | .001362 / .002046 / .013118 | 5/5 |
| workspace_file | 1 / 1 / 1 | 0 / 0 / 0 | 1 / 1 / 1 | 0 / 0 / 0 | 5 / 5 / 5 | .001315 / .001876 / .005935 | 5/5 |

Complete statistics for all numeric fields and distinct values are in
[`scenario-summary.json`](scenario-summary.json). The row-level feature table
is available as [`episode-features.csv`](episode-features.csv) and
[`episode-features.jsonl`](episode-features.jsonl).

## Normal versus side-effect comparisons

Values are medians. These labels describe fixture construction, not legitimacy.

| Comparison | execs | transitive | processes | replacements | file effects | create-like | modify | executable-set observation |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| git_status → path_hijack | 2 → 4 | 1 → 3 | 2 → 2 | 0 → 2 | 73 → 77 | 2 → 3 | 1 → 1 | same basenames (`bash`, `git`) |
| make_control → make_side_effect | 43 → 46 | 42 → 45 | 197 → 203 | 1 → 1 | 3890 → 3891 | 101 → 102 | 113 → 114 | same basename set; ranges overlap |
| git_hook_control → git_hook_effect | 3 → 5 | 2 → 4 | 2 → 3 | 1 → 2 | 54 → 58 | 8 → 9 | 6 → 7 | `pre-commit` appears |
| shell control → startup effect | 2 → 2 | 1 → 1 | 1 → 1 | 1 → 1 | 1 → 4 | 0 → 1 | 0 → 1 | identical (`bash`) |

PATH indirection is visible through extra exec generations even though the
basename set does not change. The Git hook changes topology and adds a basename.
The shell startup effect leaves topology unchanged and is visible only in file
observations. The Make marker adds file effects, but aggregate counts overlap
the normal build's natural variation; aggregate structure alone is a weak
separator for that fixture.

## Invariance and noise

Stable in this corpus:

- MATCHED classification, high confidence, complete ancestry and capture;
- direct-match executable;
- exec/process topology and executable sets for small deterministic commands;
- exec replacement count;
- file operation counts for the small workspace-file and shell fixtures.

Moderately variable:

- duration of otherwise identical small commands;
- Make process depth and process-member count;
- workspace versus non-workspace file counts in build scenarios.

High-noise or unsuitable as envelope keys:

- PID/TID, sequence numbers, and absolute timestamps;
- exact duration;
- exec, fork-only process, and file counts for Go/Make builds;
- test-binary basename presence, which changes with cache/rebuild state.

## Research questions

### RQ1: stability of repeated normal actions

Small commands were highly stable: their exec counts, topology, replacement
counts, executable sets, and retained file counts were identical across 5/5
runs. Go and Make actions were not: warm/rebuild behavior produced large count
and duration ranges even though capture and ancestry remained complete.

### RQ2: candidate expected-envelope features

Direct executable, executable basename set, replacement count, maximum process
depth, and small-command topology merit further study. File operation counts are
useful for narrow deterministic actions. Exact duration and high-volume build
counts are not stable enough without conditioning on cache/build state.

### RQ3: structural changes from indirection fixtures

PATH indirection, the Git hook, and shell startup produced repeatable structural
differences. The Make marker produced a repeatable specific file effect, but its
aggregate deltas overlapped normal build noise. The answer is therefore scenario
dependent rather than uniformly positive.

### RQ4: visibility without natural-language semantics

Yes, some differences are directly visible in kernel structure: extra exec
generations, a hook executable, or additional file observations. Structural
telemetry alone does not explain whether those differences belong in an
expected envelope.

### RQ5: effects impossible to judge structurally

All fixture effects are causally valid descendants of the reported command.
The shell startup write and Make marker are especially illustrative: ancestry
correctly attributes them, but topology provides no basis for deciding whether
they were expected. PATH wrappers and hooks are visible but can also be ordinary
tooling. Structural causality is not semantic legitimacy or action intent.

## Surprising observations

- `git status` and `git diff --stat` had deterministic but relatively large
  retained file trajectories (73 and 33 events respectively).
- PATH indirection changed exec generations without changing the unique basename
  set.
- The shell startup effect changed only file structure.
- Side-effect fixture duration was not consistently longer than its control.
- Go/Make capture stayed complete despite large natural bimodality in event
  counts, showing that variation was observed behavior rather than known loss.

## Limitations

- Five normal and three comparison runs are intentionally small samples from one
  host, kernel, repository state, Codex version, and cache history.
- Network observation was disabled; no network invariance conclusion is drawn.
- File evidence is retained-event evidence, not a complete Linux mutation audit.
- `create_or_open` is counted as create-like without claiming whether the inode
  was newly created.
- Aggregate counts discard path and operation ordering that could be useful, but
  exact local paths would overfit and reduce portability.
- The experiment does not establish behavior across kernels, architectures, or
  concurrent workload pressure.

## Reproduction

Collection scripts are intentionally separate from production analysis:

```text
research/action-residual/collect_baseline.sh
research/action-residual/collect_side_effects.sh
research/action-residual/analyze.py
```

No raw Logira databases are committed. Given the corresponding run directories,
features can be regenerated with:

```bash
LOGIRA_HOME=/path/to/logira-home \
  research/action-residual/analyze.py \
  research/action-residual/baseline-runs.jsonl \
  research/action-residual/side-effect-runs.jsonl \
  --logira ./logira \
  --features research/action-residual/episode-features.jsonl \
  --csv research/action-residual/episode-features.csv \
  --summary research/action-residual/scenario-summary.json
```

## Recommendation

**B. More baseline data or observation improvements are required.**

The small-command results justify investigating structural envelopes, but not
defining Effect Residual yet. A next research iteration should stratify Go/Make
runs by warm versus rebuild state, repeat the corpus across repository and host
states, add a localhost-only network baseline, and evaluate operation-category
sequences without exact-path overfitting. No detector or threshold should be
implemented from this corpus alone.
