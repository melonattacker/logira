# logira JSONL (v2)

`logira episode` reconstructs an execution lineage from these retained records
without changing the JSONL schema or writing derived audit events. Its separate
[Episode JSON schema and attribution rules](episodes.md) preserve source
sequence numbers and the original event payloads.

logira stores one JSON object per line in `events.jsonl` under each run directory:

`$LOGIRA_HOME/runs/<run-id>/events.jsonl`

State-changing file evidence is retained for ordinary runs; routine opens remain rule-driven, not path-watch driven.

Common fields:
- `run_id`: run identifier
- `seq`: per-run sequence number (monotonic)
- `ts`: unix nanos (UTC)
- `type`: `exec` | `process` | `file` | `net` | `detection`
- `pid`, `ppid`, `uid`: best-effort process metadata
- `summary`: short, human-oriented one-liner
- `data_json`: event-type specific JSON payload

## Exec Event (`type=exec`)

```json
{
  "run_id": "20260214-201530-bash",
  "seq": 12,
  "ts": 1771100130123456789,
  "type": "exec",
  "pid": 1234,
  "ppid": 1200,
  "uid": 1000,
  "summary": "exec bash -lc echo hi",
  "data_json": {
    "filename": "/usr/bin/bash",
    "argv": ["bash","-lc","echo hi"],
    "comm": "bash",
    "cwd": "/workspace",
    "kernel_time_ns": 1234567890,
    "cgroup_id": 4567890123
  }
}
```

`data_json` fields (best-effort):
- `filename`, `argv`, `comm`, `cwd`, `kernel_time_ns`
- `cgroup_id`: kernel cgroup id if available

## File Event (`type=file`)

```json
{
  "run_id": "20260214-201530-bash",
  "seq": 20,
  "ts": 1771100131123456789,
  "type": "file",
  "pid": 1234,
  "summary": "file open /home/u/.aws/credentials",
  "data_json": {
    "op": "open",
    "path": "/home/u/.aws/credentials",
    "pid": 1234,
    "ppid": 1200,
    "uid": 1000,
    "cgroup_id": 4567890123
  }
}
```

`data_json` fields (best-effort):
- `op`: `create` | `create_or_open` | `modify` | `rename` | `delete` | `open` | `unknown`
- `path`: affected path
- `pid`, `ppid`, `uid`: process metadata also recorded inside file detail (best-effort)
- `cgroup_id`: kernel cgroup id if available
- `size_before`, `size_after`: bytes (if known; may be absent)
- `hash_before`, `hash_after`: SHA-256 (best-effort; may be absent)
- `hash_truncated`: true when hashing was capped by `--hash-max-bytes` (may be absent)

## Net Event (`type=net`)

```json
{
  "run_id": "20260214-201530-bash",
  "seq": 40,
  "ts": 1771100132123456789,
  "type": "net",
  "pid": 1234,
  "summary": "net connect 140.82.121.4:443 bytes=0",
  "data_json": {
    "op": "connect",
    "proto": "unknown",
    "dst_ip": "140.82.121.4",
    "dst_port": 443,
    "bytes": 0,
    "cgroup_id": 4567890123
  }
}
```

`data_json` fields (best-effort):
- `op`: `connect` | `send` | `recv`
- `proto`: `tcp` | `udp` | `unknown`
- `dst_ip`, `dst_port`
- `bytes`: for `send`/`recv`
- `cgroup_id`: kernel cgroup id if available

## Detection Event (`type=detection`)

Detection events are derived by the active ruleset (observe-only): the built-in rules plus any per-run custom rules supplied via `logira run --rules`. They are written to `events.jsonl` and indexed separately in SQLite.

```json
{
  "run_id": "20260214-201530-bash",
  "seq": 41,
  "ts": 1771100132123999999,
  "type": "detection",
  "summary": "[high] R4: curl|sh pattern",
  "data_json": {
    "rule_id": "R4",
    "severity": "high",
    "message": "curl piped to shell",
    "related_event_seq": 12
  }
}
```

`data_json` fields:
- `rule_id`
- `severity`: `info` | `low` | `medium` | `high`
- `message`
- `related_event_seq`: points to the observed event `seq` that triggered the rule (best-effort)

## OS observability additions (run metadata version 5)

The envelope and existing types remain readable. `process` is an additional
observed event type; consumers must tolerate unknown types and optional fields.
Historical events are not rewritten. This version number describes run metadata,
not a migration of the JSONL envelope.

### Process lifecycle

`exec` still comes from `sched:sched_process_exec`. It adds `tid`, `tgid`,
`old_pid`, `task_start_kernel_ns`, and `first_observed_kernel_ns` when available.
`process` records `kind=fork|exit|exec_rekey`, kernel monotonic time, cgroup ID,
and task identity. Fork includes `parent_tid`, `parent_tgid`, `child_tid`, and
`parent_task_start_kernel_ns`. The fork's `task_start_kernel_ns` belongs to the
child. `exec_rekey` connects `old_pid` to the new `tid` after a non-leader exec;
it preserves the executing task's identity, not the replaced leader's identity.
A normal exec changes the program image without changing the task identity.

Birth identity is the monotonic timestamp observed at the fork tracepoint, not
`task_struct.start_time`. A missing birth remains zero/absent. For tasks that
predate attachment, `first_observed_kernel_ns` is only the first observation,
not a birth time. PIDs alone are never stable identities across reuse. Missing
parents stay unknown; fork-only tasks need not have exec records. `child_tgid`
and `clone_kind` can remain unknown, and exit `group_dead=unknown` does not prove
that an entire thread group exited. Root tasks can enter the run cgroup after
their fork, so the parent/fork record may be outside the run.

Exec and lifecycle records use separate buffers. Arrival order (`seq`, wall-clock
`ts`) is not guaranteed to be kernel causal order; use `kernel_time_ns` and the
available identities when interpreting evidence. PPID/CWD from `/proc` are
best-effort enrichments that can race with exit, exec, chdir, and PID reuse.

### File operations and retention

The daemon uses syscall tracepoints. It records correlated successful operations:

| Evidence | `op` | Meaning |
| --- | --- | --- |
| Successful `openat/openat2` with `O_CREAT|O_EXCL` | `create` | Creation confirmed |
| Successful open with `O_CREAT` alone | `create_or_open` | Creation or opening an existing file; not confirmed creation |
| Successful open with `O_TRUNC`, without `O_CREAT` | `modify` | Truncation requested by successful open |
| Positive `write/pwrite64/writev` | `modify` | Bytes accepted by syscall, with observed open-path provenance |
| Successful `truncate/ftruncate` | `modify` | Truncation, distinguished by `syscall` |
| Successful `rename/renameat/renameat2` | `rename` | `path` to `path2` |
| Successful `unlink/unlinkat` | `delete` | Name removed; not proof that open content was destroyed |

`O_CREAT|O_TRUNC` remains `create_or_open`; `flags` preserves the truncation
request. Failed operations do not become confirmed effects, and zero-byte writes
are omitted. Missing enter/exit correlation is uncertainty, not proof of an effect:
`op=unknown, correlation=incomplete`. This can include a failed syscall return.
Known missing exits are counted at session finalization.

Additive fields include `syscall`, `correlation`, `path2`, `raw_path`, `raw_path2`,
`path_resolution`, `path_resolution2`, `fd`, `dirfd`, `dirfd2`, `flags`,
`return_value`, `bytes`, `tid`, `tgid`, and `kernel_time_ns`. Zero return values may
be omitted. `task_start_kernel_ns` is reserved for identity when known; file and
network collectors currently do not infer it from a reusable PID.

All ordinary runs retain state-changing operations, ambiguous `create_or_open`,
and incomplete correlations, including unresolved paths and paths outside CWD.
Routine opens are retained only when relevant to active file detection rules.
Chdir and descriptor operations support correlation and are not persisted by
default. `--watch` does not filter events. A create-only rule does not produce a
create detection for `create_or_open`; that evidence is still retained. Existing
`modify` rules continue to match truncation, including confirmed truncating
`create_or_open` events. New rule op values include `rename`
and `create_or_open`. Credential-open rules require read-capable access.

Descriptor provenance is bounded and best-effort. Successful opens and dup calls
support later write-path attribution. `fd_open_path` denotes the name observed
at open, which may have since been renamed or unlinked. Relative descriptor paths
remain `unresolved_fd_open_path`, rather than being rebased against a later CWD.
Absolute raw paths are namespace-relative syscall arguments, not canonical host
paths. Other relative paths use best-effort `/proc` CWD/dirfd enrichment, with raw
arguments retained. Unresolved dirfds never fall back to CWD. New runs never
fall back to the run's CWD; legacy normalization remains available for old inputs.

Descriptor-cache generations are invalidated on fork, exec and close_range;
network caches are also invalidated on dup. This avoids attribution to stale
PID/FD identities at the cost of missing inherited/surviving descriptor context.
LRU eviction, `fcntl` duplication, descriptor passing, shared FD tables, concurrent
close/reuse, and operations before tracer attachment remain gaps. Paths are capped
at 255 bytes and truncation is not separately flagged. Writes without observed
open-path provenance (including pipes/sockets and inherited FDs) are omitted.
Memory-mapped writes, io_uring, splice, filesystem internals and many other effects
are not covered. A successful write is not proof of durable storage.

### Network semantics

IPv4/IPv6 address bytes and ports are decoded in network order. The BPF/userspace
wire format is versioned and size-checked. Detail adds `connect_state`, `pid`,
`tid`, `tgid`, and `kernel_time_ns`.

`connect_state=completed` means connect returned zero. `in_progress` means
`EINPROGRESS`; it does not prove establishment. UDP connect selects a peer and
is not a TCP handshake. Other failed connects are not emitted. Older records
without `connect_state` have unknown completion semantics. Protocol is inferred
only from compatible INET socket type/protocol metadata, otherwise `unknown`.

Send/receive records describe positive syscall byte counts, not packet capture.
Destination is the sendto argument or cached connect target. A cached in-progress
target does not prove connection completion. Unconnected recvfrom/sendmsg peer
addresses, accept, inherited/duplicated sockets, read/write on sockets, DNS names,
and asynchronous connection completion are not comprehensively observed.

### Coverage and loss accounting

`meta.json` and SQLite `runs.meta_json` add `coverage.process`, `coverage.file`,
and `coverage.network`. Each has `availability`, `capture`, and `known_loss`:

- `collector_forward_dropped`: full collector-to-daemon channel, per cgroup/type.
- `session_queue_dropped`: full session queue for an enabled category.
- `persistence_failures`: failed event or associated detection persistence calls.
- `correlation_failures`: incomplete file correlation and pending missing exits.

Process coverage includes exec and lifecycle events. `availability=unavailable,
capture=not_applicable` means disabled by the run or daemon. Enabled collection
starts with `availability=available,capture=unknown`; required collector startup
failures abort daemon startup. Known loss changes capture to `partial`. Even a
loss-free test capture stays `unknown`: there is no end-to-end proof of complete
kernel capture. This collector never emits `complete`.

`coverage.finalization_failures` counts shared flush/metadata/close failures;
these make enabled categories partial. Buffered JSONL is flushed before final
coverage is written. On close failure, the sidecar is updated where possible and
StopRun reports an error; an unavailable SQLite database may retain earlier
metadata. A failed sidecar write can leave only SQLite metadata. When storage is
unwritable, no reliable persisted loss report is possible.

Counters describe failure occurrences, not distinct missing events: correlation
and forwarding failures can overlap. They exclude deliberate retention filtering.
File tracer stage counters are system-wide diagnostics, not per-run loss counts.
Ring-buffer reservation failures, map pressure, decode errors and late events at
shutdown are not all attributed to runs. Session close flushes a snapshot of each ring buffer through userspace delivery
barriers before draining admitted queue entries. It does not establish an atomic
end of kernel activity. Zero counters
or an empty event stream must never be interpreted as proof of no activity.
Old runs without coverage have unknown coverage, not complete coverage.

The tracer output channels (2,048 entries), daemon forwarding channel (16,384),
and session queues (8,192 per run) are bounded. Broader syscall observation adds
system-wide tracing overhead, bounded kernel maps/ring buffers, and more disk
traffic for mutation-heavy runs. Retention filtering occurs after collection;
it reduces persisted routine opens, not the cost of observing them. No event
coalescing or per-path deduplication is claimed.

## Access-mode and shutdown corrections

Successful correlated `openat/openat2` observations add `access_mode`:
`read_only`, `write_only`, `read_write`, `path_only` (O_PATH), or `unknown`.
This describes descriptor access, not an actual read or write. `op=open` still
means an open without a confirmed mutation, including write-only opens.
Credential rules F020–F024 use `require_read_access: true`: write-only, O_PATH,
and unknown modes do not match. Read-only and read-write opens can produce
read-access risk alerts, whose messages now say “read-capable open”. Older file
observations without access metadata retain legacy matching behavior; their
access mode and any actual reads remain unknown.

For a correlated successful `O_CREAT|O_TRUNC` open, the event remains
`create_or_open`. The rule engine also considers its truncation as `modify`
evidence when matching op filters. It matches each rule at most once, leaves
message `file.op` and stored evidence unchanged, and never satisfies a
create-only rule on this basis. Failed, incomplete and O_PATH observations do
not gain modification evidence from these flags.

Relative-path enrichment now uses `path_resolution=proc_cwd_best_effort` or
`proc_dirfd_best_effort` (and the corresponding `path_resolution2`). These names
explicitly describe a userspace lookup after the syscall. The resulting `path`
is a candidate location, not an authoritative syscall-time path; chdir, dirfd
reuse, process exit/PID reuse, and mount changes can race with enrichment.
`raw_path` and `dirfd` retain the original argument evidence. Absolute syscall
arguments and unresolved FD-open provenance keep their existing distinct labels.

On stop, cgroup routing stays active while flush markers from each ring-buffer
reader traverse its output channel and the daemon routing queue. Markers cannot
be dropped due to backpressure. Only after acknowledgement does the session
close admission and drain all admitted events. This is a per-reader snapshot,
not a global kernel cutoff: in-flight/new operations can still arrive later.
The total drain wait is bounded at two seconds. Metadata adds
`coverage.delivery_drain=snapshot|failed|unavailable`; a failed/timed-out drain
increments `coverage.drain_failures` and makes enabled categories partial.

Events reaching a closing session after admission closes but before routing is
retired increment per-category `known_loss.shutdown_dropped`, persisted with the
final coverage snapshot. Routing and retirement are synchronized so no caller
can retain a stale session pointer and silently enqueue after that snapshot.
Subsequent late deliveries and collector forwarding drops are counted separately
for the most recent 256 retired cgroups. `logira status` / `status --json` expose
these supplemental counters as `late_run_loss` with per-run process/file/network
counts, restricted to the owner (root may see all). The first late delivery per
category is logged; final totals are logged on eviction or cgroup ID reuse.

Late counters are in-memory supplements, not updates to finalized metadata:
the root daemon does not reopen finalized user-owned audit files. Retired routes
and their collector loss targets expire after 256 newer retirements, ID reuse,
or daemon restart. Events beyond that accounting window cannot be attributed
to the old run. Kernel losses before decode, operations beyond the flush snapshot,
and unavailable collector drain support remain limitations. Neither a successful
snapshot drain nor zero late counters implies complete capture or no activity.
