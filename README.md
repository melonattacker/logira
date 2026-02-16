# logira

**Runtime security for AI agents.**

`logira` is a Linux-only CLI that records what an AI agent actually did while it ran:
the processes it executed, files it touched, and network activity it initiated.
Each run is auto-saved locally so you can review it later (`view`), search it (`query`), and understand detections (`explain`).

## What is this for?

- You want an audit trail when running agents with permissive modes like `codex --yolo` or `claude --dangerously-skip-permissions`.
- You want to review or share "what happened" after an agent run, without relying on the agent's own narrative.
- You want to debug surprising changes by looking at the timeline of exec/file/net activity.
- You want lightweight, observe-only runtime monitoring during local development and testing.

## Default Detections

logira includes an opinionated, observe-only default ruleset aimed at auditing AI agent runs.

- Credential and secrets writes: `~/.ssh`, `~/.aws`, kube/gcloud/docker config, `.netrc`, `.git-credentials`, registry creds.
- Persistence and config changes: writes under `/etc`, systemd units, cron, user autostart entries, shell startup files.
- Temp droppers: executable files created under `/tmp`, `/dev/shm`, `/var/tmp`.
- Suspicious exec patterns: `curl|sh`, `wget|sh`, tunneling/reverse shell tools and flags, base64 decode with shell hints.
- Network egress: suspicious destination ports and cloud metadata endpoint access.

## Quick Start

Build:

```bash
make build
```

Start the root daemon (required for tracing):

```bash
sudo ./logirad
```

If you run `logirad` via systemd, set BPF object paths via environment (or place the `collector/linux/*/trace_bpf*.o` files in a location `logirad` can find). See `packaging/systemd/logirad.service`.

Run an agent under audit as your normal user (events are auto-saved):

```bash
./logira run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'
```

Run Codex CLI:

```bash
./logira run -- codex --yolo "Update the README to be clearer and add examples."
```

Run Claude Code CLI:

```bash
./logira run -- claude --dangerously-skip-permissions "Find and fix flaky tests."
```

List runs:

```bash
./logira runs
```

View and explain the last run:

```bash
./logira view last
./logira explain last
```

Query events:

```bash
./logira query --run last --type detection
./logira query --run last --type net --dest 140.82.121.4:443
./logira query --run last --contains curl
```

## Commands

- `logira run -- <command...>`: run a command under audit and auto-save a new run
- `logira runs`: list saved runs
- `logira view [last|<run-id>]`: view a run summary
- `logira query [filters...]`: search events in a run
- `logira explain [last|<run-id>]`: explain detections for a run

## Where Is Data Stored?

Default home directory: `~/.logira` (override: `LOGIRA_HOME`)

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

- JSONL schema: [`docs/jsonl.md`](docs/jsonl.md)
- SQLite schema: [`docs/sqlite.md`](docs/sqlite.md)
- Development notes (BPF generation, tests): [`docs/development.md`](docs/development.md)

## Notes

- Linux kernel 5.8+ is required.
- Tracing requires the root daemon `logirad` to be running; `logira run` itself does not require sudo.
- If BPF object files are missing, set `LOGIRA_EXEC_BPF_OBJ` / `LOGIRA_NET_BPF_OBJ` / `LOGIRA_FILE_BPF_OBJ`.
