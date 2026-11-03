# Execution Episodes (JSON schema version 1)

An Episode reconstructs a user-selected execution and its observed descendant
lineage. It describes retained OS observations, not intent, authorization,
expected behavior, safety, or maliciousness. It works with ordinary shell, build,
and service processes without an agent runtime.

## Run, Process Graph, and Episode

- A **Run** contains the observations retained during a capture session. Cgroup
  tracking primarily establishes this capture scope.
- The **Process Graph** reconstructs task instances, observed fork relationships,
  exec generations, exits, and non-leader exec identity transitions within a Run.
- An **Episode** selects one observed exec in that graph. A Run can support many
  explicit selections, including overlapping Episodes. This command does not
  partition a Run automatically.

Find an exec and select its source sequence:

```bash
logira query last --type exec --limit 50
logira episode last --exec-seq 12
logira episode last --exec-seq 12 --json
logira episode 20261103-000000-shell --exec-seq 12 --json
logira episode --exec-seq 12 --json last
```

The run selector defaults to `last`. `--exec-seq` is required and must identify
an exec, not a fork, file, network, or detection record. The command is offline;
it does not require a daemon, root privileges, or access to live `/proc`.

## Identity and generations

`process_members` are **tasks**, including individual threads. A shared TGID
does not merge threads. `task_id` is a run-local analysis reference based on the
earliest supporting source sequence; it is not an OS identifier and is stable
for the same stored input. Each task retains its observed identity aliases.

The strongest identity is TID plus `task_start_kernel_ns`. That timestamp is
the observation at the fork tracepoint, **not** an authoritative kernel task
creation timestamp. `first_observed_kernel_ns` can distinguish an observed
incarnation when birth is missing, but never becomes a birth timestamp.
Absent identity fields remain unknown. Unanchored legacy observations are not
all combined into a single `(pid, 0)` task.

An exec replaces an executable within a task. Each observed exec has a separate
source sequence and, when ordering is established, a one-based `generation`
within that task's observed history. The selected root may therefore have a
generation greater than one. `previous_exec_seq` connects observed replacements;
it is not a fork edge or proof that no intermediate exec was lost. Unknown exec
ordering leaves both generation and replacement links null.

`exec_rekey` changes the executing task's numerical TID after a non-leader exec.
The old and new identities remain aliases of that task; the displaced leader
remains a different task. The paired exec can have an earlier kernel timestamp
than the lifecycle rekey record. Identity evidence, rather than timestamp
equality, establishes the transition. An exec's `old_pid` can support an alias
without a retained rekey record. An unmatched rekey creates no synthetic exec
and prevents an earlier executable from being assigned across that boundary.
Transitions without either birth or first-observation identity remain unresolved;
the analyzer does not attach them to the displaced leader using its new TID.

Numerical TID reuse ends the old instance's ownership interval when a new
independently identified incarnation is observed. It does not manufacture an
exit. Missing exits and `group_dead=unknown` never prove whole-group termination.

## Membership

The root task participates from the selected exec onward. Later proven exec
generations in that task are included. Expansion follows resolved **observed
forks downward**, including intermediate tasks with no exec. A child enters at
its fork; subsequent descendants remain members even after the root exits.

Ancestors, siblings, earlier activity in the root task, and children forked
before the root exec are excluded. Cgroup equality, shared TGID, executable
names, PPID guesses, wall-clock windows, and sequence proximity do not establish
membership. Unknown fork/exec boundary ordering produces uncertainty. Legacy
PPID links can expose candidates but never create a resolved edge or member.
Candidates are checked against known lifetime and numerical-identity boundaries
at the PPID observation or fork, rather than at later child activity. A known
birth, exit, reuse, or rekey contradiction excludes the candidate; missing
timing alone does not. Children can still have activity after their parent
exits. Rejecting a tentative ancestry hint does not establish that a disconnected
task is unrelated: its activity remains run-scoped and unattributable unless
other evidence establishes a relationship.

The root can be inspected with missing ancestry. Task lifecycle references may
predate the root because they establish its identity; only `exec_members`,
`file_events`, and `network_events` describe included execution/activity.
Relationships for a member can reference a parent task outside the Episode.
That reference does not include the parent or its activity.

## Activity attribution and counting

Resolution first matches the emitting task, then its observed exec generation.
An exact identity is strongest. When birth is absent, TID plus kernel time can
select one compatible, independently anchored task lifetime. This matters for
PR1 file/network observations, which normally omit birth identity. PID/TGID
alone only identifies candidates, never a definite emitting thread.

Attribution values:

| Value | Meaning |
| --- | --- |
| `task_and_exec_generation` | A member task and one compatible observed exec generation are established. |
| `task_instance_only` | Membership is established, but the precise generation is missing or ambiguous. Fork-only tasks receive no inherited or synthetic exec. |
| `uncertain` | Task identity or Episode membership remains unresolved. These records appear only in `uncertain_events`. |

Kernel ordering takes priority over arrival order. Equal or missing kernel
times do not settle an exec boundary using sequence tie-breaking. Ambiguity
between two generations inside an Episode can retain task-only attribution;
ambiguity across the selected root boundary cannot.

Each of `summary.file` and `summary.network` partitions **all retained events
of that type in the analyzed Run snapshot** into four disjoint buckets:

| Counter | Meaning |
| --- | --- |
| `attributed` | Included in the corresponding attributed array, with either definite attribution state above. |
| `uncertain` | A concrete candidate connection exists, but attribution is unresolved; included in `uncertain_events`. |
| `unrelated` | Evidence places the observation outside this Episode: for example, a resolved ancestor/sibling, pre-root activity, or an observed pre-root child branch. These are **not attribution failures**. |
| `unattributable` | Residual Run observations lacking enough identity or relationship evidence, without a concrete candidate connection to this Episode. |

For each type:

```text
observed = attributed + uncertain + unrelated + unattributable
```

`unattributable_reasons` counts only the last bucket, across file and network
events, distinguishing missing/ambiguous identity from
`unresolved_episode_relationship`. A disconnected task with missing ancestry
is not declared unrelated merely because no path was reconstructed. Its task
identity may be known even when its Episode relationship is not.

These counters are relative to the chosen root. They are not separate totals
to add to attributed arrays or loss counters. An uncertain event is not also
counted as unattributable. Excluded events are not automatically failures.
Run-wide unknown observations do not imply activity by the selected lineage.

## JSON contract

JSON output is one object, with no progress messages. No derived Episode is
persisted back into the audit log. Consumers should tolerate additive fields.

| Field | Contents |
| --- | --- |
| `schema_version` | `1`, independent of stored Run metadata versions. |
| `run_id`, `root_exec_seq` | The explicit selection. |
| `root_exec` | Exec record containing `event`, `task_id`, nullable `generation`, and nullable `previous_exec_seq`. Observed filename/arguments are in `event.data_json`. |
| `process_members` | `task_id`, observed `identities`, `fork_seqs`, `exit_seqs`, `exec_seqs`, `rekey_seqs`, `group_dead`, `identity_conflict`, and Episode `entry_seq`/`entry_kind`. |
| `relationships` | Fork `seq`, optional kernel time, `parent_identity`, nullable `parent_task_id`, `child_task_id`, observed `clone_kind`, and resolution status. |
| `exec_members` | Included observed exec records, in source-sequence order. |
| `file_events`, `network_events` | Attributed records: original `event`, nullable task/exec/generation references, `attribution`, `basis`, and optional `reason`. |
| `uncertain_events` | Candidate file/network evidence with `attribution=uncertain`, reasons, and source sequences. Not included in definite totals. |
| `summary` | Member counts, the activity partitions above, residual reasons, and counts of ignored unrelated event types. |
| `coverage` | `scope=run`, normalized `reported` capture metadata, conservative `ancestry`, and `activity_scope=retained_events`. |
| `limitations` | Structured `code`, optional source `seq`, and optional `task_id`. |
| `analysis_source` | `events` (`jsonl`/`sqlite`), `metadata` (`meta.json`/`sqlite`/`missing`), `max_seq`, and `finalized`. False finalized means finalization is absent or unknown. |

Empty collections are `[]` or `{}`. Nullable derived references use `null`.
Identity fields use the stored convention: omitted/zero means unknown, never
an actual TID or birth of zero. Original event envelopes and `data_json` retain
their source omission semantics and unknown additive fields.

Tasks are ordered by their supporting sequence; activity and exec arrays by
source sequence; relationships by fork sequence; limitations by code/task/seq.
Task `exec_seqs` follow reconstructed exec ordering, but only non-null generation
fields assert a resolved order. JSON array presentation is not a causal clock.
Equivalent input permutations produce identical output.

## Example

Consider retained observations from a shell launching a subshell and a command:

| Seq | Observation |
| --- | --- |
| 12 | Root shell exec. |
| 13 | Shell forks a subshell. |
| 14 | Subshell successfully opens `out.txt` with `O_CREAT`, retained as `create_or_open`. |
| 15 | Subshell forks a child. |
| 17 | Child execs `curl`. |
| 18 | Child's connect returns `EINPROGRESS`. |

Selecting exec 12 includes three tasks and two observed execs. The subshell has
no synthetic exec. Event 14 has `task_instance_only` attribution and still does
not prove file creation. Event 18 can reference exec 17, but its preserved
`connect_state=in_progress` does not prove an established connection.
Selecting exec 17 excludes the shell, subshell, and event 14.

## Coverage, storage, and limitations

Reported capture states and loss counters come from the Run, not an independent
Episode capture. Missing metadata becomes unknown. Even a historical reported
`complete` state is unverified; the analyzer never upgrades it into a guarantee.
Ancestry is `unknown` or `partial`, never inferred complete from zero losses.
An empty Episode activity array is not proof of inactivity.

Original file operations, syscall correlation, path-resolution uncertainty,
descriptor provenance, access modes, network connection states, and byte counts
remain unchanged. An open is not a confirmed read; `create_or_open` is not a
confirmed creation; a successful write is not proof of durable storage. Only
retained observations are included. Unobserved normal exec replacements and
entirely lost task lifetimes cannot be reconstructed.

The reader uses all JSONL records in the file-size snapshot taken at open, or
an uncapped, read-only SQLite snapshot if JSONL is absent. There is no 100,000
event query limit. Malformed JSONL fails rather than silently switching stores.
An unfinished run remains a provisional snapshot; retry after finalization if
a partially written record fails decoding. JSONL records exceeding 8 MiB fail
explicitly. Memory usage is proportional to the input; graph construction uses
indexed identities and adjacency traversal rather than all-pairs matching.

`meta.json` is preferred; missing sidecar metadata can fall back to SQLite.
The sources are identified in the output. The reader does not reconcile
divergent stores, initialize databases, migrate schemas, or repair captures.
SQLite WAL read restrictions can still cause a clear error when no JSONL source
is available. Existing capture/query behavior is unchanged.

Future reporting or provider-specific analysis may consume this object. This
version performs no automatic partitioning, inherited-image inference, scoring,
intent analysis, anomaly classification, HTML generation, or provider ingestion.
