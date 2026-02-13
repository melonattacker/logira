package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/melonattacker/agentlogix/collector"
	"github.com/melonattacker/agentlogix/internal/logging"
)

type pair struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type netSummary struct {
	Target string `json:"target"`
	Proto  string `json:"proto"`
	Conns  int    `json:"connections"`
	Sent   int64  `json:"sent_bytes"`
	Recv   int64  `json:"recv_bytes"`
}

type summaryOut struct {
	ExecCommands []pair       `json:"exec_commands"`
	FileOps      []pair       `json:"file_ops"`
	FilePaths    []pair       `json:"file_paths"`
	Network      []netSummary `json:"network"`
}

type netAgg struct {
	Proto string
	Conns int
	Sent  int64
	Recv  int64
}

func SummarizeCommand(ctx context.Context, args []string) error {
	_ = ctx

	fs := flag.NewFlagSet("summarize", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var logPath string
	var asJSON bool
	fs.StringVar(&logPath, "log", "", "log file or directory")
	fs.BoolVar(&asJSON, "json", false, "emit JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(logPath) == "" {
		return fmt.Errorf("--log is required")
	}

	files, err := logging.CollectLogFiles(logPath)
	if err != nil {
		return err
	}
	events, err := logging.ReadEvents(files)
	if err != nil {
		return err
	}

	execCounts := map[string]int{}
	fileOps := map[string]int{}
	filePaths := map[string]int{}

	netAggMap := map[string]*netAgg{}

	for _, ev := range events {
		switch ev.Type {
		case collector.EventTypeExec:
			d, err := parseExecDetail(ev.Detail)
			if err != nil {
				continue
			}
			key := d.Filename
			if len(d.Argv) > 0 {
				head := d.Argv
				if len(head) > 3 {
					head = head[:3]
				}
				key = strings.Join(head, " ")
			}
			if strings.TrimSpace(key) == "" {
				key = "<unknown>"
			}
			execCounts[key]++
		case collector.EventTypeFile:
			d, err := parseFileDetail(ev.Detail)
			if err != nil {
				continue
			}
			if d.Op == "" {
				d.Op = "unknown"
			}
			fileOps[d.Op]++
			if d.Path != "" {
				filePaths[d.Path]++
			}
		case collector.EventTypeNet:
			d, err := parseNetDetail(ev.Detail)
			if err != nil {
				continue
			}
			target := fmt.Sprintf("%s:%d", d.DstIP, d.DstPort)
			if d.DstIP == "" {
				target = "<unknown>"
			}
			agg, ok := netAggMap[target]
			if !ok {
				agg = &netAgg{Proto: d.Proto}
				netAggMap[target] = agg
			}
			switch d.Op {
			case "connect":
				agg.Conns++
			case "send":
				agg.Sent += d.Bytes
			case "recv":
				agg.Recv += d.Bytes
			}
		}
	}

	out := summaryOut{
		ExecCommands: topPairs(execCounts, 20),
		FileOps:      topPairs(fileOps, 20),
		FilePaths:    topPairs(filePaths, 20),
		Network:      topNetwork(netAggMap, 50),
	}

	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}

	fmt.Fprintf(os.Stdout, "Exec commands:\n")
	for _, p := range out.ExecCommands {
		fmt.Fprintf(os.Stdout, "  %5d  %s\n", p.Count, p.Key)
	}
	fmt.Fprintf(os.Stdout, "\nFile operations:\n")
	for _, p := range out.FileOps {
		fmt.Fprintf(os.Stdout, "  %5d  %s\n", p.Count, p.Key)
	}
	fmt.Fprintf(os.Stdout, "\nTop file paths:\n")
	for _, p := range out.FilePaths {
		fmt.Fprintf(os.Stdout, "  %5d  %s\n", p.Count, p.Key)
	}
	fmt.Fprintf(os.Stdout, "\nNetwork targets:\n")
	for _, n := range out.Network {
		fmt.Fprintf(os.Stdout, "  conn=%d sent=%d recv=%d proto=%s target=%s\n", n.Conns, n.Sent, n.Recv, n.Proto, n.Target)
	}
	return nil
}

func topPairs(m map[string]int, n int) []pair {
	out := make([]pair, 0, len(m))
	for k, v := range m {
		out = append(out, pair{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func topNetwork(m map[string]*netAgg, n int) []netSummary {
	out := make([]netSummary, 0, len(m))
	for k, v := range m {
		out = append(out, netSummary{Target: k, Proto: v.Proto, Conns: v.Conns, Sent: v.Sent, Recv: v.Recv})
	}
	sort.Slice(out, func(i, j int) bool {
		ci := out[i].Conns*1000 + int(out[i].Sent+out[i].Recv)
		cj := out[j].Conns*1000 + int(out[j].Sent+out[j].Recv)
		if ci == cj {
			return out[i].Target < out[j].Target
		}
		return ci > cj
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}
