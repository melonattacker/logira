//go:build linux

package exectrace

//go:generate bash -lc 'set -e; INC="-I/usr/include -I."; UM=$(uname -m 2>/dev/null || true); if [ -n "$UM" ] && [ -d "/usr/include/${UM}-linux-gnu" ]; then INC="$INC -I/usr/include/${UM}-linux-gnu"; fi; MA=$(gcc -print-multiarch 2>/dev/null || true); if [ -n "$MA" ] && [ -d "/usr/include/$MA" ]; then INC="$INC -I/usr/include/$MA"; fi; go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" trace _trace.bpf.c -- $INC'
