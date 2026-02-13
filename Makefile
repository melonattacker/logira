BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go

.PHONY: build test generate

build:
	go build ./cmd/agentlogix

test:
	go test ./...

generate:
	cd collector/linux/exec && $(BPF2GO) -cc clang -cflags "-O2 -g -Wall" trace trace.bpf.c -- -I/usr/include -I.
	cd collector/linux/net && $(BPF2GO) -cc clang -cflags "-O2 -g -Wall" trace trace.bpf.c -- -I/usr/include -I.
