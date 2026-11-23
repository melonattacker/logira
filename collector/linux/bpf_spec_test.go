//go:build linux

package linuxcollector

import (
	"bytes"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

// Parse the shipped objects without root or loading programs into the kernel.
// This catches generator/loader incompatibility for both ELF byte orders.
func TestBPFCollectionSpecs(t *testing.T) {
	for _, tracer := range []string{"exec", "net", "filetrace"} {
		for _, endian := range []string{"bpfel", "bpfeb"} {
			t.Run(tracer+"/"+endian, func(t *testing.T) {
				path := filepath.Join(tracer, "trace_"+endian+".o")
				spec, err := ebpf.LoadCollectionSpec(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(spec.Programs) == 0 || spec.Maps["events"] == nil || spec.Maps["events"].Type != ebpf.RingBuf {
					t.Fatal("missing programs or event ring buffer")
				}
				if tracer == "exec" {
					prog := spec.Programs["trace_sched_exec"]
					if prog == nil || prog.SectionName != "tracepoint/sched/sched_process_exec" {
						t.Fatal("missing required sched_process_exec tracepoint")
					}
				}

				// Regression for CVE-2026-10722: overflowing BTF bounds must
				// return an error, not panic. Mutate a copy, never the artifact.
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				obj, err := elf.NewFile(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				defer obj.Close()
				btf := obj.Section(".BTF")
				if btf == nil || btf.Size < 24 {
					t.Fatal("missing BTF header")
				}
				for _, offset := range []uint64{8, 16} { // type and string offset/length
					bad := bytes.Clone(data)
					header := bad[btf.Offset : btf.Offset+24]
					obj.ByteOrder.PutUint32(header[offset:offset+4], ^uint32(0)-15)
					obj.ByteOrder.PutUint32(header[offset+4:offset+8], 32)
					if _, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(bad)); err == nil {
						t.Fatalf("accepted overflowing BTF range at offset %d", offset)
					}
				}
			})
		}
	}
}
