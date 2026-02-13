package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/melonattacker/agentlogix/internal/cli"
)

func main() {
	os.Exit(realMain())
}

func realMain() int {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <run|summarize|replay> [args]\n", os.Args[0])
		return 2
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "run":
		err = cli.RunCommand(ctx, os.Args[2:])
	case "summarize":
		err = cli.SummarizeCommand(ctx, os.Args[2:])
	case "replay":
		err = cli.ReplayCommand(ctx, os.Args[2:])
	case "help", "-h", "--help":
		fmt.Fprintf(os.Stdout, "usage: %s <run|summarize|replay> [args]\n", os.Args[0])
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		return 2
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
