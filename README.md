# AgentLogix

AgentLogix is a Linux-focused **runtime security auditor** for AI agent executions (observe-only).
It records process execs, file changes, network activity, and derived detections, and stores each run under a dedicated directory with **JSONL + SQLite** for fast querying.

## Quick Start (Linux)

Build:

```bash
make build
```

Trace a command (events are auto-saved):

```bash
sudo ./agentlogix run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'
```

List runs:

```bash
./agentlogix runs
```

View the last run:

```bash
./agentlogix view last
./agentlogix explain last
```

Query (SQLite-first, JSONL fallback):

```bash
./agentlogix query --run last --type detection
./agentlogix query --run last --type net --dest 140.82.121.4:443
./agentlogix query --run last --contains curl
```

## Storage Layout

Default state directory: `~/.agentlogix` (override: `AGENTLOGIX_HOME`)

Each run is stored at:

```
~/.agentlogix/
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
- If BPF object files are missing, set `AGENTLOGIX_EXEC_BPF_OBJ` / `AGENTLOGIX_NET_BPF_OBJ`.
- `--log` is deprecated: it optionally copies `events.jsonl` to a user-provided path for backward workflows.
