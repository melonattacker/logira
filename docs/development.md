# Development (Linux)

This doc is for contributors.

## Requirements

- Linux kernel 5.8+
- Root (or appropriate capabilities) to run tracers
- Go 1.22+
- clang/llvm to regenerate eBPF objects
- Linux UAPI headers (if you see missing `asm/types.h`, install your distro's libc/kernel headers packages)

## Build

```bash
make build
```

## Generate eBPF (only needed if `.o` files are missing or BPF changed)

```bash
make generate
```

This uses `bpf2go` and produces `trace_bpfel.o`/`trace_bpfeb.o` plus generated Go files. The BPF C inputs are named with a leading underscore (e.g. `_trace.bpf.c`) so `go build` ignores them.
Commit the generated artifacts so end users do not need clang.

## Tests

Unit tests:

```bash
go test ./...
```

Integration tests (Linux + root):

```bash
go test -tags=integration ./collector/linux -v
```

## Troubleshooting

- AgentLogix state directory can be overridden:
  - `AGENTLOGIX_HOME=/path/to/state`
- If runtime fails to load BPF objects, set explicit paths:
  - `AGENTLOGIX_EXEC_BPF_OBJ=/abs/path/to/trace_bpfel.o`
  - `AGENTLOGIX_NET_BPF_OBJ=/abs/path/to/trace_bpfel.o`
- fanotify may fail on some systems/policies; the watcher falls back to inotify (PID attribution will be lost).
