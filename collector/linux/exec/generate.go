//go:build linux

package exectrace

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" trace trace.bpf.c -- -I/usr/include -I.
