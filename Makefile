BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go

.PHONY: build test generate

# Avoid permission issues if users ran Go tooling under sudo earlier.
GOCACHE_DIR ?= $(CURDIR)/.cache/go-build

MULTIARCH := $(shell gcc -print-multiarch 2>/dev/null)
UNAME_M := $(shell uname -m)
BPF_INCLUDES := -I/usr/include -I.
ifneq ($(strip $(UNAME_M)),)
ifneq ($(wildcard /usr/include/$(UNAME_M)-linux-gnu),)
BPF_INCLUDES += -I/usr/include/$(UNAME_M)-linux-gnu
endif
endif
ifneq ($(strip $(MULTIARCH)),)
BPF_INCLUDES += -I/usr/include/$(MULTIARCH)
endif

build:
	GOCACHE=$(GOCACHE_DIR) go build ./cmd/logira

test:
	GOCACHE=$(GOCACHE_DIR) go test ./...

generate:
	cd collector/linux/exec && GOCACHE=$(GOCACHE_DIR) $(BPF2GO) -go-package exectrace -cc clang -cflags "-O2 -g -Wall" trace _trace.bpf.c -- $(BPF_INCLUDES)
	cd collector/linux/net && GOCACHE=$(GOCACHE_DIR) $(BPF2GO) -go-package nettrace -cc clang -cflags "-O2 -g -Wall" trace _trace.bpf.c -- $(BPF_INCLUDES)
