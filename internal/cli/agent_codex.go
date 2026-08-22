package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	agentcodex "github.com/melonattacker/logira/internal/agent/codex"
	"github.com/melonattacker/logira/internal/ipc"
)

type codexStreamResult struct {
	Stats   ipc.AgentTelemetryStats
	Warning error
}

func validateAgentCommand(provider string, argv []string) error {
	if provider == "" {
		return nil
	}
	if provider != "codex" {
		return fmt.Errorf("unsupported --agent %q (expected codex)", provider)
	}
	if len(argv) == 0 || filepath.Base(argv[0]) != "codex" {
		return fmt.Errorf("--agent codex requires an explicit codex executable")
	}
	if len(argv) < 2 || argv[1] != "exec" {
		return fmt.Errorf("--agent codex requires 'codex exec --json'")
	}
	hasJSON := false
	for _, arg := range argv[2:] {
		if arg == "--json" {
			hasJSON = true
		}
	}
	if !hasJSON {
		return fmt.Errorf("--agent codex requires 'codex exec --json'")
	}
	return nil
}

func consumeCodexJSONL(ctx context.Context, src io.Reader, passthrough io.Writer, sessionID string) codexStreamResult {
	result := codexStreamResult{Stats: ipc.AgentTelemetryStats{Capture: "complete", Interpretation: "complete"}}
	reader := bufio.NewReaderSize(src, 64*1024)
	var warnings []error
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			if _, writeErr := passthrough.Write(line); writeErr != nil {
				result.Stats.Capture = "partial"
				warnings = append(warnings, fmt.Errorf("write stdout: %w", writeErr))
			}
			record := bytes.TrimSuffix(line, []byte{'\n'})
			record = bytes.TrimSuffix(record, []byte{'\r'})
			if len(bytes.TrimSpace(record)) != 0 {
				result.Stats.LinesSeen++
				parsed := agentcodex.ParseLine(record)
				if parsed.Malformed {
					result.Stats.Malformed++
					result.Stats.Interpretation = "partial"
				}
				if !parsed.KnownSchema && !parsed.Malformed {
					result.Stats.UnknownSchema++
					result.Stats.Interpretation = "partial"
				}
				if parsed.RawTruncated {
					result.Stats.RawTruncated++
				}
				appendCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				appendErr := ipc.AppendAgentEvent(appendCtx, sessionID, parsed.Detail)
				cancel()
				if appendErr != nil {
					result.Stats.AppendFailures++
					result.Stats.Capture = "partial"
					warnings = append(warnings, appendErr)
				} else {
					result.Stats.LinesPersisted++
				}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				result.Stats.Capture = "partial"
				warnings = append(warnings, fmt.Errorf("read stdout: %w", err))
			} else if ctx.Err() != nil {
				result.Stats.Capture = "partial"
				warnings = append(warnings, fmt.Errorf("stdout interrupted: %w", ctx.Err()))
			}
			break
		}
	}
	if result.Stats.LinesSeen == 0 {
		result.Stats.Interpretation = "partial"
	}
	result.Warning = errors.Join(warnings...)
	return result
}
