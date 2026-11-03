# Standalone HTML audit reports

`logira report` renders retained Run observations as one self-contained HTML
file. The report opens directly through `file://`: it has embedded CSS, no
JavaScript, no external fonts or images, no CDN, and no network or backend API
dependency.

Reports are generic Linux OS audit views. They do not depend on an agent
runtime, infer intent, or introduce a second process-membership or attribution
model.

## Commands and report modes

Run Overview is the default:

```bash
logira report last
logira report <run-id>
```

It describes the Run as a whole: metadata and finalization state, exact retained
event counts, reported coverage, Process Graph limitations, detections, and the
observed exec list. It does not choose a root exec or assign Run-wide activity
to an Episode.

Select an observed exec sequence to add Episode Detail:

```bash
logira query <run-id> --type exec
logira report <run-id> --exec-seq 11
logira report <run-id> --exec-seq 11 --output ./audit.html
```

Episode Detail uses the same `episode.Build` result as `logira episode`. It adds
the selected root, confirmed task lineage, observed exec generations, fork-only
tasks, attributed file and network evidence, uncertain candidate evidence, and
Run-relative unrelated and unattributable counts.

Default filenames are:

- `logira-report-<run-id>.html`
- `logira-report-<run-id>-exec-<seq>.html`

An existing destination is not replaced unless `--force` is supplied. Report
files are created with mode `0600`. A destination symlink is never followed and
is rejected even with `--force`; its target is not modified. `--force` replaces
only a regular file, after the complete new report has been rendered to a
private same-directory temporary file.

## Process and Episode semantics

The execution view is task-oriented and uses only Process Graph identities and
Episode membership:

- A fork-only task has no observed executable. The report does not inherit its
  parent's executable or manufacture a synthetic exec.
- Multiple exec generations remain attached to the same observed task.
- A non-leader `exec_rekey` keeps its identity aliases and is not drawn as a
  newly forked child.
- Tasks are not merged only because they share a TGID.
- Only an `observed_fork` relationship whose parent and child are both Episode
  members is drawn as a confirmed tree edge.
- Unresolved or outside ancestry is labeled rather than inferred.
- `clone_kind=unknown` remains unknown; it is not relabeled as a process or
  thread creation.

The HTML uses iterative, flat tree traversal so deeply nested build processes
cannot overflow the Go template stack. Visual indentation is capped, with the
actual depth disclosed.

## Attribution, uncertainty, and counting

Definite file and network tables come only from the Episode's `file_events` and
`network_events`. Each group retains the difference between:

- `task_and_exec_generation`
- `task_instance_only`

Candidate evidence from `uncertain_events` appears in a separate section. It is
not included in definite activity. Unrelated and unattributable Run observations
are counts, not Episode effects.

For each activity type:

```text
observed = attributed + uncertain + unrelated + unattributable
```

Grouping is visual compression, not a causal or security judgment. File groups
preserve task/exec attribution, operation, paths, access mode, syscall and
correlation state, path-resolution state, return value, and observed bytes.
Network groups preserve attribution, operation, protocol, destination,
connection state, and observed bytes. Counts are observation counts, not unique
files, connections, or durable effects.

The report does not reinterpret evidence:

- A successful open is not automatically a confirmed read.
- `create_or_open` is not guaranteed creation.
- A successful write is not proof of durable storage.
- Relative or unresolved paths remain uncertain.
- A connect observation is not automatically an established connection.
- UDP connect does not prove a packet was transmitted.
- IP addresses are not converted to hostnames, and UDP/443 is not labeled QUIC.

Detections remain Run-scoped rule results. A detection displays an Episode
evidence badge only when its retained `related_event_seq` directly references a
definitely attributed event. A reference to candidate evidence remains labeled
uncertain. Time proximity never creates a link.

## Coverage and provisional snapshots

The report displays Run metadata faithfully, including each collector's
`availability`, `capture`, and known-loss counters, plus delivery-drain and
finalization state. Missing values become `unknown`; `capture=unknown` is not a
success state. Zero known losses do not prove complete capture, and an empty
activity section does not prove inactivity.

Runs without an end timestamp are allowed and clearly labeled provisional.
Missing metadata is labeled as unknown finalization. The analysis reader takes
the same uncapped, read-only JSONL or SQLite snapshot used by Execution Episode
analysis. A malformed or partially written JSONL record fails clearly rather
than silently switching sources.

## HTML limits and source evidence

All aggregate counts use the complete retained snapshot. To keep ordinary
reports usable, visible HTML is bounded:

| Content | Limit |
| --- | ---: |
| Observed exec rows | 500 |
| Episode task rows | 2,000 |
| File groups | 1,000 |
| Network groups | 500 |
| Uncertain groups | 500 |
| Detection groups | 250 |
| Source sequences per group | 100 |
| Long command/argv preview | 4 KiB |
| Raw JSON preview | 8 KiB |
| Final HTML file | 64 MiB |

Every applied display limit reports exact omitted group, observation, sequence,
or byte counts. Exceeding the final HTML limit fails without replacing an old
destination. Source sequences remain visible, and the report provides `query`
and `episode --json` commands for uncapped inspection.

## Security and privacy

Stored commands, arguments, paths, summaries, and detection messages are
untrusted. The renderer uses Go's context-aware `html/template` escaping and
never treats stored text as HTML, CSS, URLs, or attributes. Raw event JSON is
escaped text inside `<pre>`. A restrictive Content Security Policy disables
scripts, connections, objects, frames, media, images, fonts, forms, and base
URL changes; only the embedded style block is allowed.

Reports can still contain sensitive telemetry. Store and share them like the
underlying audit data. Logira does not claim comprehensive secret redaction.
