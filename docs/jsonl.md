# logira JSONL (v2)

logira stores one JSON object per line in `events.jsonl` under each run directory:

`$LOGIRA_HOME/runs/<run-id>/events.jsonl`

File event retention is rule-driven (based on active file detection rules), not path-watch driven.

Common fields:
- `run_id`: run identifier
- `seq`: per-run sequence number (monotonic)
- `ts`: unix nanos (UTC)
- `type`: `exec` | `file` | `net` | `detection`
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
- `op`: `create` | `modify` | `delete` | `open`
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
