package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"testing"

	"github.com/melonattacker/logira/internal/cli"
)

func TestCommandExitCode(t *testing.T) {
	if got, ok := commandExitCode(flag.ErrHelp); !ok || got != 0 {
		t.Fatalf("help got code=%d ok=%v, want code=0 ok=true", got, ok)
	}

	if got, ok := commandExitCode(&cli.ExitCodeError{Code: 42}); !ok || got != 42 {
		t.Fatalf("exit error got code=%d ok=%v, want code=42 ok=true", got, ok)
	}

	wrapped := fmt.Errorf("wrapped: %w", &cli.ExitCodeError{Code: 17})
	if got, ok := commandExitCode(wrapped); !ok || got != 17 {
		t.Fatalf("wrapped exit error got code=%d ok=%v, want code=17 ok=true", got, ok)
	}

	if got, ok := commandExitCode(errors.New("other")); ok || got != 0 {
		t.Fatalf("other error got code=%d ok=%v, want code=0 ok=false", got, ok)
	}
}

func TestRootHelpDiscoversInspectWorkflow(t *testing.T) {
	var out bytes.Buffer
	printRootHelp(&out, "logira")
	for _, want := range []string{"inspect    Inspect one agent action", "logira inspect last action:1"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Fatalf("root help missing %q:\n%s", want, out.String())
		}
	}
}
