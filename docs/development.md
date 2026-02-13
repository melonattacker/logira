# Development (Linux)

This doc is for contributors.

## Requirements

- Linux kernel 5.8+
- Root (or appropriate capabilities) to run tracers
- Go 1.22+
- clang/llvm to regenerate eBPF objects

## Build

```bash
make build
```

## Generate eBPF (only needed if `.o` files are missing or BPF changed)

```bash
make generate
```

This uses `bpf2go` and produces `trace_bpfel.o`/`trace_bpfeb.o` plus generated Go files.
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

- If runtime fails to load BPF objects, set explicit paths:
  - `AGENTLOGIX_EXEC_BPF_OBJ=/abs/path/to/trace_bpfel.o`
  - `AGENTLOGIX_NET_BPF_OBJ=/abs/path/to/trace_bpfel.o`
- fanotify may fail on some systems/policies; the watcher falls back to inotify (PID attribution will be lost).
