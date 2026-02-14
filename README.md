# logira

logira is a Linux-focused **runtime security auditor** for AI agent executions (observe-only).
It records process execs, file changes, network activity, and derived detections, and stores each run under a dedicated directory with **JSONL + SQLite** for fast querying.

## Quick Start (Linux)

Build:

```bash
make build
```

Trace a command (events are auto-saved):

```bash
sudo ./logira run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'
```

List runs:

```bash
./logira runs
```

View the last run:

```bash
./logira view last
./logira explain last
```

Query (SQLite-first, JSONL fallback):

```bash
./logira query --run last --type detection
./logira query --run last --type net --dest 140.82.121.4:443
./logira query --run last --contains curl
```

## Storage Layout

Default state directory: `~/.logira` (override: `LOGIRA_HOME`)

Each run is stored at:

```
~/.logira/
  runs/<run-id>/
    events.jsonl
    index.sqlite
    meta.json
```

`run-id` format: `YYYYMMDD-HHMMSS-<tool>`

## Docs

- JSONL schema: `docs/jsonl.md`
- SQLite schema: `docs/sqlite.md`
- Development notes (BPF generation, tests): `docs/development.md`

## Notes

- Linux kernel 5.8+ is required.
- Running `run` typically requires root (eBPF + fanotify).
- If BPF object files are missing, set `LOGIRA_EXEC_BPF_OBJ` / `LOGIRA_NET_BPF_OBJ`.
- `--log` is deprecated: it optionally copies `events.jsonl` to a user-provided path for backward workflows.
