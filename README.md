# AgentLogix

AgentLogix is a Linux-focused CLI auditor for AI agent executions.
It records process execs, file changes, and network activity and writes **JSONL** logs.

## Quick Start (Linux)

Build:

```bash
make build
```

Trace a command:

```bash
./agentlogix run --log out.jsonl -- bash -lc 'echo hi > x.txt; curl -s https://example.com >/dev/null'
```

Summarize:

```bash
./agentlogix summarize --log out.jsonl
```

Replay:

```bash
./agentlogix replay --log out.jsonl --pretty
```

## Docs

- JSONL schema: `docs/jsonl.md`
- Development notes (BPF generation, tests): `docs/development.md`

## Notes

- Linux kernel 5.8+ is required.
- Running `run` typically requires root (eBPF + fanotify).
- If BPF object files are missing, set `AGENTLOGIX_EXEC_BPF_OBJ` / `AGENTLOGIX_NET_BPF_OBJ`.
