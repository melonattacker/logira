# AGENTS.md (logira)

This repository implements **logira**, a **Linux-only** CLI auditor that records:
- process `exec` events
- file changes
- network activity

Each `run` is auto-saved under a per-run directory with **JSONL + SQLite** for auditing and fast search.

## Non-Negotiables

- Linux exec tracing MUST use eBPF tracepoint: `sched:sched_process_exec`.
- Collector MUST be OS-swappable:
  - `collector/common.go`: interfaces + event model
  - `collector/linux/collector.go`: Linux implementation
  - `collector/fallback_stub.go`: non-Linux stub
- CLI MUST expose:
  - `logira run -- <agent command...>` (auto-saves run)
  - `logira runs`
  - `logira view [last|<run-id>]`
  - `logira query [filters...]`
  - `logira explain [last|<run-id>]`
- Logs MUST be JSONL with:
  - `run_id`, `seq`, `ts` (unix nanos), `type`, `summary`, `data_json`
  - `type`: `exec` | `file` | `net` | `detection`

## Current Architecture (Source of Truth)

- CLI:
  - `cmd/logira/main.go`
  - `internal/cli/run.go`, `internal/cli/runs.go`, `internal/cli/view.go`, `internal/cli/query.go`, `internal/cli/explain.go`

- Run storage:
  - base dir: `~/.logira` (override: `LOGIRA_HOME`)
  - per-run dir: `~/.logira/runs/<run-id>/`
  - metadata: `internal/runs/`

- Storage/index:
  - JSONL writer/reader: `internal/storage/jsonl.go`, `internal/storage/jsonl_read.go`
  - SQLite (modernc, no CGO): `internal/storage/sqlite.go`
  - Queries: `internal/storage/query.go`

- Detection (observe-only):
  - rules engine: `internal/detect/engine.go`

- Event model:
  - `collector/common.go` defines `collector.Event` and `collector.Collector`.
  - `internal/model/events.go` defines the JSON shapes used in `detail`.

- Linux collector:
  - `collector/linux/collector.go` composes:
    - exec tracer: `collector/linux/exec/`
    - net tracer: `collector/linux/net/`
    - file watcher: `collector/linux/file/`

### Linux exec tracer

- BPF C: `collector/linux/exec/_trace.bpf.c`
- Hooks:
  - `tracepoint/sched/sched_process_exec` (required)
  - `tracepoint/syscalls/sys_enter_execve`
  - `tracepoint/syscalls/sys_enter_execveat`
- Userspace loader: `collector/linux/exec/loader.go`
- Notes:
  - PPID is best-effort enriched in userspace by reading `/proc/<pid>/stat`.
  - CWD is best-effort enriched in userspace by reading `/proc/<pid>/cwd`.

### Linux net tracer

- BPF C: `collector/linux/net/_trace.bpf.c`
- Hooks:
  - connect: `sys_enter_connect`, `sys_exit_connect`
  - send: `sys_enter_sendto/sys_exit_sendto`, `sys_enter_sendmsg/sys_exit_sendmsg`
  - recv: `sys_enter_recvfrom/sys_exit_recvfrom`, `sys_enter_recvmsg/sys_exit_recvmsg`
- Userspace loader: `collector/linux/net/loader.go`
- Notes:
  - Destination is best-effort; for send/recv we cache `pid+fd -> dst` from connect.
  - `proto` is currently best-effort and may be `unknown`.

### Linux file watcher

- `collector/linux/file/watcher.go`
- Strategy:
  - fanotify first (captures PID via metadata), with `FAN_EVENT_ON_CHILD` for subtree.
  - inotify fallback (no PID attribution), recursively watches directories.
- Notes:
  - Hashing is best-effort and capped by `--hash-max-bytes`.
  - `hash_before` comes from an in-memory cache and may be absent.

## BPF Build / Generated Artifacts Policy

The plan requires that generated BPF artifacts are **committed** so end users do not need clang.

- Generation entrypoints:
  - `collector/linux/exec/generate.go`
  - `collector/linux/net/generate.go`
  - `Makefile` target `generate`

Expected generated outputs (commit them):
- `collector/linux/exec/trace_bpfel.o` (and likely `trace_bpfeb.o`)
- `collector/linux/net/trace_bpfel.o` (and likely `trace_bpfeb.o`)
- `trace_*.go` files created by `bpf2go` in those directories

Runtime loader looks for (in this order):
- `collector/linux/*/trace_bpfel.o`
- `collector/linux/*/trace.bpf.o`

Override paths with:
- `LOGIRA_EXEC_BPF_OBJ`
- `LOGIRA_NET_BPF_OBJ`

## Development Rules

- Always run on Linux for real validation.
- Run `gofmt` over Go sources.
- Keep event volume bounded (channels are bounded and may drop under pressure).
- Avoid changing JSONL schema casually; update `docs/jsonl.md` if you do.

## Test / Validation Checklist

### Unit (no root)
- `go test ./...`

### Integration (Linux + root)
- Generate BPF once (if missing): `make generate`
- Run integration tests: `go test -tags=integration ./collector/linux -v`

### Manual smoke test
- Build: `make build`
- Run:
  - `sudo ./logira run -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'`
  - `./logira view last`
  - `./logira query --run last --type detection`

## Known Gaps / Follow-ups (keep explicit)

- eBPF code currently focuses on correctness/best-effort data. Some fields can be `unknown`.
- Cross-kernel portability should be validated on kernel 5.8+ targets.
- If you change BPF event structs, keep userspace decoder in sync.
