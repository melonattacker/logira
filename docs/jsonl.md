# logira JSONL

logira stores one JSON object per line in `events.jsonl` under each run directory:

`$LOGIRA_HOME/runs/<run-id>/events.jsonl`

For ordinary runs, file event retention is rule-driven (based on active file
detection rules), not path-watch driven. Agent runs additionally retain
workspace access and state-changing file observations, including unresolved
paths and incomplete syscall correlation evidence.

Common fields:
- `run_id`: run identifier
- `seq`: per-run sequence number (monotonic)
- `ts`: unix nanos (UTC)
- `type`: `agent` | `process` | `exec` | `file` | `net` | `detection`
- `provenance`: `agent_runtime_reported` | `kernel_observed` | `logira_derived`
- `pid`, `ppid`, `uid`: best-effort process metadata
- `summary`: short, human-oriented one-liner
- `data_json`: event-type specific JSON payload

Provenance is observational: Codex JSONL is runtime/harness-reported telemetry,
not direct evidence of model or user intent.

## Agent Event (`type=agent`)

Agent events are present only when a supported agent telemetry mode is enabled,
currently with `logira run --agent codex -- codex exec --json ...`. The normalized
payload includes `provider`, `kind`, `event_type`, emitted thread/item IDs, and
the fields applicable to that item (`command`, `status`, `exit_code`, `text`, or
`todo_items`). Verified Codex 0.147 kinds are `thread_started`, `turn_started`,
`turn_completed`, `command_execution`, `agent_message`, and `todo_list`.

Unknown well-formed and malformed records are preserved without inventing
semantics. `raw_sha256` hashes the complete input record. `raw_truncated` only
describes preservation of the raw payload; it does not by itself mean agent
capture was partial when all correlation fields were parsed and persisted.

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
- `tid`, `tgid`, `old_pid`, `task_start_kernel_ns`, `first_observed_kernel_ns`
- `cgroup_id`: kernel cgroup id if available

## Process Event (`type=process`)

Process events preserve kernel task lifecycle observations independently of
exec. `kind` is `fork`, `exit`, or `exec_rekey`. A task instance is identified
by `(tid, task_start_kernel_ns)`, where `task_start_kernel_ns` is the
`bpf_ktime_get_ns()` value captured at `sched_process_fork`. It is not wall
clock time or a `task_struct` start field. Tasks that existed before tracing
may omit it and instead carry `first_observed_kernel_ns`.

Fork records preserve the kernel-observed parent/child TIDs even when no
userspace `/proc` metadata can be obtained. `clone_kind` is `thread_clone`,
`process_fork`, or `unknown`. Exit records are task exits; `group_dead` remains
`unknown` when the kernel tracepoint does not expose it structurally.

An `exec_rekey` with different `old_pid` and `tid` records Linux de-threading
during a multi-threaded exec. It preserves the task start timestamp while
moving the identity to the post-exec TID.

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
    "syscall": "openat",
    "correlation": "complete",
    "path": "/home/u/.aws/credentials",
    "raw_path": ".aws/credentials",
    "path_resolution": "dirfd",
    "fd": 7,
    "dirfd": 4,
    "pid": 1234,
    "tid": 1234,
    "tgid": 1234,
    "ppid": 1200,
    "uid": 1000,
    "cgroup_id": 4567890123
  }
}
```

`data_json` fields (best-effort):
- `op`: `create` | `create_or_open` | `modify` | `rename` | `delete` | `open` | `chdir` | `unknown`
- `syscall`: the observed syscall (`openat`, `write`, `renameat2`, etc.)
- `correlation`: `complete` when a bounded enter state was paired with its
  exit, or `incomplete` when the exit was observed without its enter
- `path`, `path2`: affected path(s); `path2` is used by rename operations
- `raw_path`: original relative kernel path, when applicable
- `path_resolution`: how a relative path was resolved (`dirfd`, `cwd`,
  `task_cwd`, `fd_provenance`, or an explicit unresolved/legacy state).
  Successful-open FD provenance is run-local and bounded; unresolved dirfds
  never fall back to CWD.
- `fd`, `dirfd`, `dirfd2`: returned/operated-on descriptor and directory descriptors,
  when supplied by the kernel tracer
- `pid`, `tid`, `tgid`, `ppid`, `uid`, `kernel_time_ns`: task/process metadata (best-effort)
- `flags`, `return_value`, `bytes`: syscall result metadata when applicable
- `cgroup_id`: kernel cgroup id if available
- `size_before`, `size_after`: bytes (if known; may be absent)
- `hash_before`, `hash_after`: SHA-256 (best-effort; may be absent)
- `hash_truncated`: true when hashing was capped by `--hash-max-bytes` (may be absent)

Successful effects are emitted only after syscall exit: open requires
`ret >= 0`, writes require `ret > 0`, and rename/unlink/truncate require
`ret == 0`. `O_CREAT|O_EXCL` is `create`; `O_CREAT` without exclusivity is
`create_or_open`; `O_TRUNC` is `modify`. A write-capable open alone is not
reported as a modification; successful `write`, `pwrite64`, or `writev`
provides that evidence.

Version 5 never resolves an unresolved relative path against the run CWD.
Resolution uses the actual dirfd, live `/proc` metadata, or run-local task CWD
and successful-open FD provenance. Otherwise the raw path is retained with an
explicit unresolved state.

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
    "connect_state": "completed",
    "proto": "tcp",
    "dst_ip": "140.82.121.4",
    "dst_port": 443,
    "bytes": 0,
    "cgroup_id": 4567890123,
    "pid": 1234,
    "tid": 1234,
    "tgid": 1234,
    "kernel_time_ns": 9876543210
  }
}
```

`data_json` fields (best-effort):
- `op`: `connect` | `send` | `recv`
- `connect_state`: `completed` | `in_progress` for connect events. A successful
  connect exit is `completed`; `EINPROGRESS` is retained as structured
  `in_progress` evidence. Both states populate the minimal fd-to-destination
  cache used by later send/recv events.
- `proto`: `tcp` | `udp` | `unknown`. Linux records the socket type at
  successful `socket(2)` return and invalidates the minimal fd metadata after
  successful `close(2)`; inherited, duplicated, or otherwise unobserved fds
  can remain `unknown`.
- `dst_ip`, `dst_port`: IPv4 or IPv6 destination and host-readable port
- `bytes`: the signed syscall return value for `send`/`recv`
- `cgroup_id`: kernel cgroup id if available
- `pid`, `tid`, `tgid`: kernel-observed process and task identifiers
- `kernel_time_ns`: BPF monotonic observation timestamp

The Linux net probe uses a fixed, architecture-independent wire ABI (version
1, 72 bytes). Address and port bytes are copied from `sockaddr` unchanged in
network byte order: port 443 is `01 bb`, and port 18080 is `46 a0`. Go decodes
the port as big-endian. Host-order timestamp, cgroup, task, uid, and byte-count
scalars are converted to big-endian before emission; a signed byte count uses
the two's-complement `uint64` representation. C compile-time size/offset
assertions and Go raw-byte fixtures lock the two sides to the same layout.

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

## Run coverage metadata

Agent-enabled `meta.json` files separate `coverage.agent.capture` from
`coverage.agent.interpretation`. Unknown schemas and fully persisted malformed
records make interpretation partial without claiming that the telemetry stream
was lost.

Process, file, and network coverage each record `availability`, `capture`, and
known loss split into `collector_forward_dropped`, `session_queue_dropped`,
`persistence_failures`, and file `correlation_failures`. Kernel capture
`complete` narrowly means that Logira
knows of no loss after the relevant collector boundary. It is not proof that
the kernel/BPF path was globally lossless.
