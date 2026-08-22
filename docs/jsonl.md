# logira JSONL

logira stores one JSON object per line in `events.jsonl` under each run directory:

`$LOGIRA_HOME/runs/<run-id>/events.jsonl`

File event retention is rule-driven (based on active file detection rules), not path-watch driven.

Common fields:
- `run_id`: run identifier
- `seq`: per-run sequence number (monotonic)
- `ts`: unix nanos (UTC)
- `type`: `agent` | `exec` | `file` | `net` | `detection`
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
    "raw_path": ".aws/credentials",
    "path_resolution": "dirfd",
    "fd": 7,
    "dirfd": 4,
    "pid": 1234,
    "ppid": 1200,
    "uid": 1000,
    "cgroup_id": 4567890123
  }
}
```

`data_json` fields (best-effort):
- `op`: `create` | `modify` | `delete` | `open`
- `path`: affected path
- `raw_path`: original relative kernel path, when applicable
- `path_resolution`: how a relative path was resolved (`dirfd`, `cwd`, or an
  explicit unresolved/legacy state). The returned `fd` is not used for path
  resolution because it may be closed and reused before userspace handles the
  event.
- `fd`, `dirfd`: returned descriptor and the `openat(2)` directory descriptor,
  when supplied by the kernel tracer
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

## Run coverage metadata

Agent-enabled `meta.json` files separate `coverage.agent.capture` from
`coverage.agent.interpretation`. Unknown schemas and fully persisted malformed
records make interpretation partial without claiming that the telemetry stream
was lost.

Process, file, and network coverage each record `availability`, `capture`, and
known loss split into `collector_forward_dropped`, `session_queue_dropped`, and
`persistence_failures`. Kernel capture `complete` narrowly means that Logira
knows of no loss after the relevant collector boundary. It is not proof that
the kernel/BPF path was globally lossless.
