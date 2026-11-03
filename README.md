# logira

**OS-level runtime auditing for unpredictable automation.**

<p align="center">
  <img src="https://github.com/user-attachments/assets/d8b53356-e0ee-4a7e-b232-8548ba216610" width="900">
</p>

`logira` is an observe-only Linux CLI that records runtime `exec`, `file`, and `net` events via eBPF. It helps you see what actually happened during AI agent runs and other forms of automation, with per-run local storage for auditing, post-run review, search, and detection triage.

## What is logira?

- eBPF-based runtime collection of process execution, file activity, and network activity.
- cgroup v2 run-scoped tracking, so events can be attributed to a single audited run.
- Per-run local storage in JSONL and SQLite for timeline review and fast querying.
- Built-in default detection rules, with optional custom YAML rules.
- Observe-only by design: logira records and detects, but does not enforce or block.

## Why logira?

- Audit what an AI agent actually executed, changed, and connected to during a run (for example, `codex --yolo` or `claude --dangerously-skip-permissions`).
- Keep a trustworthy execution trail that does not depend on the agent’s own textual narrative.
- Detect risky behavior patterns such as credential access, destructive commands, persistence changes, and suspicious network egress.
- Review and share forensic evidence after a run using structured event history and detection results.
- Add lightweight runtime auditing to local automation or CI tasks without changing workload behavior.

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

After reinstall / upgrade:

- First install: no extra step is usually needed (`install.sh` runs `systemctl enable --now`).
- Reinstall/upgrade over an existing install: restart `logirad` to ensure the new binary is running.

```bash
sudo systemctl daemon-reload
sudo systemctl restart logirad.service
sudo systemctl status logirad.service --no-pager
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
- `logira episode [last|<run-id>] --exec-seq <seq> [--json]`: reconstruct one observed execution lineage

### Execution Episodes

A Run contains the capture session's retained observations. A Process Graph
reconstructs observed task identities and relationships within that Run. An
Execution Episode selects one exec and follows its observed descendants,
including fork-only tasks and later executable replacements.

```bash
./logira query last --type exec
./logira episode last --exec-seq 12
./logira episode last --exec-seq 12 --json
```

Episodes report attributable file/network evidence and explicitly separate
uncertain, unrelated, and unattributable observations. Ancestors and siblings
do not become members. Missing ancestry or empty activity does not prove
inactivity. This is offline, general-purpose OS analysis, independent of agent
runtimes and without security or intent judgments.

See [Episode identity, attribution, counting, and JSON semantics](docs/episodes.md)
for the stable output format, legacy limitations, and a shell/descendant example.

### Rules
- built-in default ruleset is always active (`internal/detect/rules/default_rules.yaml`)
- optional per-run custom rules can be appended with `logira run --rules <yaml-file>`
- sample custom rules and trial commands: [`examples/rules/README.md`](examples/rules/README.md)
- state-changing file evidence is retained; routine opens remain rule-driven; `--watch` is deprecated compatibility only

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

## License
Apache License 2.0. See [LICENSE](LICENSE) for details.

eBPF programs under `collector/linux/` are dual-licensed: Apache-2.0 OR GPL-2.0-only. 

This ensures compatibility with the Linux kernel when loading eBPF programs that require GPL-only helpers.
### OS observation scope

Ordinary runs record process fork/exec/exit evidence and state-changing file
operations, while routine file opens remain subject to detection-rule retention.
Use `logira query --run last --type process` for lifecycle records. Network events
preserve IPv4/IPv6 destinations and distinguish completed connect syscalls from
nonblocking attempts. Saved run metadata reports per-category known losses.

Logira provides evidence within its observation scope, not complete Linux
filesystem or network auditing. Missing events do not prove absence of activity.
See [event semantics and coverage limitations](docs/jsonl.md#os-observability-additions-run-metadata-version-5).
Install the daemon and regenerated BPF objects together; older object layouts
are not compatible with the new loaders. Kernel 5.8+ and architecture portability
still require privileged runtime validation on the target system.
