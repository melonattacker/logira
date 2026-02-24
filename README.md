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
You can also append your own per-run rules YAML with `logira run --rules <file>`.

- Credential and secrets writes: `~/.ssh`, `~/.aws`, kube/gcloud/docker config, `.netrc`, `.git-credentials`, registry creds.
- Sensitive credential reads: SSH private keys, AWS credentials/config, kubeconfig, docker config, `.netrc`, `.git-credentials`.
- Persistence and config changes: writes under `/etc`, systemd units, cron, user autostart entries, shell startup files.
- Temp droppers: executable files created under `/tmp`, `/dev/shm`, `/var/tmp`.
- Suspicious exec patterns: `curl|sh`, `wget|sh`, tunneling/reverse shell tools and flags, base64 decode with shell hints.
- Agent safety destructive patterns: `rm -rf`, `git clean -fdx`, `find -delete`, `mkfs`, `terraform destroy`, and similar commands.
- Network egress: suspicious destination ports and cloud metadata endpoint access.

## Installation
### from script (recommended)

Option1. Install via the convenicent script:

```bash
curl -fsSL https://raw.githubusercontent.com/melonattacker/logira/main/install.sh | sudo bash
```

Option2. Manual install from a release tarball:

```bash
tar -xzf logira_vX.Y.Z_linux-<arch>.tar.gz
cd logira_vX.Y.Z_linux-<arch>
sudo ./install-local.sh
```

### from source

Build:

```bash
make build
```

Start the root daemon (required for tracing):

```bash
sudo ./logirad
```

<details>
<summary>How to run `logirad` via systemd</summary>

To run the root daemon in the background, install the unit file from `packaging/systemd/logirad.service`.

```bash
# 1) Generate eBPF objects (only needed if missing)
make generate

# 2) Install the systemd unit
sudo install -D -m 0644 packaging/systemd/logirad.service /etc/systemd/system/logirad.service

# 3) Install the daemon binary (unit defaults to /usr/local/bin/logirad)
sudo install -m 0755 ./logirad /usr/local/bin/logirad

# 4) (Recommended) Point systemd at the eBPF .o files via an environment file.
# This avoids relying on the service working directory.
sudo mkdir -p /etc/logira
sudo tee /etc/logira/logirad.env >/dev/null <<'EOF'
LOGIRA_EXEC_BPF_OBJ=/absolute/path/to/collector/linux/exec/trace_bpfel.o
LOGIRA_NET_BPF_OBJ=/absolute/path/to/collector/linux/net/trace_bpfel.o
LOGIRA_FILE_BPF_OBJ=/absolute/path/to/collector/linux/filetrace/trace_bpfel.o
EOF

# 5) Enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now logirad

# Follow logs
sudo journalctl -u logirad -f

# Check status
systemctl status logirad --no-pager

# Stop + disable
sudo systemctl stop logirad
sudo systemctl disable --now logirad
```
</details>

## Usage

Run an agent under audit as your normal user (events are auto-saved):

```bash
./logira run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'
./logira run --rules ./my-rules.yaml -- bash -lc 'cat ~/.aws/credentials >/dev/null'
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
./logira view last --ts both
./logira view last --color always
./logira explain last
./logira explain last --show-related
./logira explain last --drill 35
```

Query events:

```bash
./logira query last --type detection
./logira query last --type net --dest 140.82.121.4:443
./logira query last --related-to-detections --type net
./logira query last --contains curl
```

## Commands

- `logira run -- <command...>`: run a command under audit and auto-save a new run
- `logira runs`: list saved runs
- `logira view [last|<run-id>]`: run dashboard (use `--raw` for legacy text)
- `logira query [last|<run-id>] [filters...]`: search events with type-specific table output
- `logira explain [last|<run-id>]`: grouped detections by default (`--show-related`, `--drill`)

Rules:
- built-in default ruleset is always active (`internal/detect/rules/default_rules.yaml`)
- optional per-run custom rules can be appended with `logira run --rules <yaml-file>`
- sample custom rules and trial commands: [`examples/rules/README.md`](examples/rules/README.md)
- file event retention is rule-driven by file rules; `--watch` is deprecated compatibility only

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
- Custom rule syntax: [`docs/rules.md`](docs/rules.md)
- Development notes (BPF generation, tests): [`docs/development.md`](docs/development.md)

## Notes

- Linux kernel 5.8+ is required.
- systemd is required (the root daemon `logirad` is expected to run under systemd for normal installs).
- cgroup v2 is required (check with `logira status`).
- Tracing requires the root daemon `logirad` to be running; `logira run` itself does not require sudo.
- If BPF object files are missing, set `LOGIRA_EXEC_BPF_OBJ` / `LOGIRA_NET_BPF_OBJ` / `LOGIRA_FILE_BPF_OBJ`.

## Installed Paths (defaults)

The installer places:

- binaries: `/usr/local/bin/logira`, `/usr/local/bin/logirad`
- BPF objects: `/usr/local/lib/logira/bpf/`
- systemd unit: `/etc/systemd/system/logirad.service`
- environment file: `/etc/logira/logirad.env` (sets `LOGIRA_EXEC_BPF_OBJ`, `LOGIRA_NET_BPF_OBJ`, `LOGIRA_FILE_BPF_OBJ`)
