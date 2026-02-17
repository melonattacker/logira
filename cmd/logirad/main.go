//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/melonattacker/logira/collector"
	"github.com/melonattacker/logira/internal/ipc"
	"github.com/melonattacker/logira/internal/logirad"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	var sock string
	var enableExec bool
	var enableFile bool
	var enableNet bool
	flag.StringVar(&sock, "sock", ipc.SockPath(), "unix socket path (default: /run/logira.sock; override: LOGIRA_SOCK)")
	flag.BoolVar(&enableExec, "exec", true, "enable exec tracing")
	flag.BoolVar(&enableFile, "file", true, "enable file tracing")
	flag.BoolVar(&enableNet, "net", true, "enable network tracing")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg := collector.Config{
		EnableExec: enableExec,
		EnableFile: enableFile,
		EnableNet:  enableNet,
		// watch paths are per-run, filtered in userspace.
	}

	col := collector.New(cfg)
	if err := col.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "collector init: %v\n", err)
		return 1
	}

	events := make(chan collector.Event, 16384)
	if err := col.Start(ctx, events); err != nil {
		fmt.Fprintf(os.Stderr, "collector start: %v\n", err)
		return 1
	}
	defer col.Stop(context.Background())

	mgr := logirad.NewSessionManager(col)
	go func() {
		for ev := range events {
			mgr.RouteEvent(ev)
		}
	}()

	srv := logirad.NewServer(sock, mgr, logirad.ServerConfig{EnableExec: enableExec, EnableFile: enableFile, EnableNet: enableNet})
	if err := srv.ListenAndServe(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		return 1
	}
	return 0
}
