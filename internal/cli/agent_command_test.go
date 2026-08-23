package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melonattacker/logira/internal/model"
	"github.com/melonattacker/logira/internal/storage"
)

const codexStdoutHelperEnv = "LOGIRA_TEST_CODEX_STDOUT_HELPER"

func TestCodexStdoutHelperProcess(t *testing.T) {
	mode := os.Getenv(codexStdoutHelperEnv)
	if mode == "" {
		return
	}
	count, err := strconv.Atoi(os.Getenv("LOGIRA_TEST_CODEX_STDOUT_COUNT"))
	if err != nil {
		os.Exit(125)
	}
	_, _ = os.Stdout.Write(codexJSONLFixture(count))
	if mode == "block" {
		for {
			time.Sleep(time.Hour)
		}
	}
	exitCode, err := strconv.Atoi(os.Getenv("LOGIRA_TEST_CODEX_EXIT_CODE"))
	if err != nil {
		os.Exit(125)
	}
	os.Exit(exitCode)
}

func TestSlowCodexStdoutIsDrainedBeforeWait(t *testing.T) {
	const recordCount = 512
	runDir := t.TempDir()
	store, err := storage.Open(storage.OpenParams{RunID: "slow-agent", RunDir: runDir, StartTS: 1, MetaJSON: `{}`})
	if err != nil {
		t.Fatal(err)
	}

	cmd := codexStdoutHelperCommand(context.Background(), recordCount, "exit", 0)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	var passthrough bytes.Buffer
	done := make(chan codexStreamResult, 1)
	go func() {
		done <- consumeCodexJSONLWithAppender(context.Background(), stdout, &passthrough, "slow-agent", func(_ context.Context, _ string, detail model.AgentDetail) error {
			// Deliberately make persistence slower than the helper's writes. The
			// completion channel, not this delay, provides synchronization.
			time.Sleep(100 * time.Microsecond)
			data, marshalErr := json.Marshal(detail)
			if marshalErr != nil {
				return marshalErr
			}
			_, appendErr := store.AppendAgent(storage.NowUnixNanos(), "test agent message", data)
			return appendErr
		})
	}()

	result, waitErr := waitForAgentTelemetryAndCommand(cmd, done)
	if waitErr != nil {
		t.Fatalf("Wait: %v", waitErr)
	}
	if result.Warning != nil {
		t.Fatalf("unexpected capture warning: %v", result.Warning)
	}
	if result.Stats.Capture != "complete" || result.Stats.Interpretation != "complete" {
		t.Fatalf("coverage=%+v", result.Stats)
	}
	if result.Stats.LinesSeen != recordCount || result.Stats.LinesPersisted != recordCount {
		t.Fatalf("stats=%+v, want %d lines", result.Stats, recordCount)
	}
	if !bytes.Equal(passthrough.Bytes(), codexJSONLFixture(recordCount)) {
		t.Fatal("stdout passthrough was not byte-for-byte identical")
	}
	if err := store.Close(2, `{}`); err != nil {
		t.Fatal(err)
	}
	events, err := storage.ReadJSONL(filepath.Join(runDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != recordCount {
		t.Fatalf("persisted events=%d, want %d", len(events), recordCount)
	}
	for i, event := range events {
		if event.Type != storage.TypeAgent {
			t.Fatalf("event %d type=%q", i, event.Type)
		}
		var detail model.AgentDetail
		if err := json.Unmarshal(event.DataJSON, &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Kind != "agent_message" || detail.ItemID != fmt.Sprintf("item_%04d", i) {
			t.Fatalf("event %d detail=%+v", i, detail)
		}
	}
}

func TestAgentCommandExitStatusIsPreserved(t *testing.T) {
	cmd := codexStdoutHelperCommand(context.Background(), 8, "exit", 23)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan codexStreamResult, 1)
	go func() {
		done <- consumeCodexJSONLWithAppender(context.Background(), stdout, &bytes.Buffer{}, "exit-status", func(context.Context, string, model.AgentDetail) error {
			return nil
		})
	}()
	result, waitErr := waitForAgentTelemetryAndCommand(cmd, done)
	if result.Warning != nil || result.Stats.LinesPersisted != 8 {
		t.Fatalf("stream result=%+v", result)
	}
	if got := exitCodeFromErr(waitErr); got != 23 {
		t.Fatalf("exit code=%d, want 23; waitErr=%v", got, waitErr)
	}
}

func TestCanceledAgentCommandDoesNotHangWaitingForStdout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := codexStdoutHelperCommand(ctx, 1, "block", 0)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	firstPersisted := make(chan struct{})
	var once sync.Once
	streamDone := make(chan codexStreamResult, 1)
	go func() {
		streamDone <- consumeCodexJSONLWithAppender(ctx, stdout, &bytes.Buffer{}, "canceled", func(context.Context, string, model.AgentDetail) error {
			once.Do(func() { close(firstPersisted) })
			return nil
		})
	}()
	waitDone := make(chan struct {
		result codexStreamResult
		err    error
	}, 1)
	go func() {
		result, waitErr := waitForAgentTelemetryAndCommand(cmd, streamDone)
		waitDone <- struct {
			result codexStreamResult
			err    error
		}{result: result, err: waitErr}
	}()

	select {
	case <-firstPersisted:
		cancel()
	case <-time.After(5 * time.Second):
		t.Fatal("helper did not emit its first record")
	}

	select {
	case got := <-waitDone:
		if got.err == nil {
			t.Fatal("canceled command unexpectedly succeeded")
		}
		if got.result.Stats.LinesSeen != 1 || got.result.Stats.LinesPersisted != 1 {
			t.Fatalf("stats=%+v", got.result.Stats)
		}
		if got.result.Warning == nil || !strings.Contains(got.result.Warning.Error(), "context canceled") {
			t.Fatalf("warning=%v", got.result.Warning)
		}
		if strings.Contains(got.result.Warning.Error(), "file already closed") {
			t.Fatalf("Wait closed stdout before the reader completed: %v", got.result.Warning)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("canceled command did not terminate")
	}
}

func codexStdoutHelperCommand(ctx context.Context, count int, mode string, exitCode int) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCodexStdoutHelperProcess$")
	cmd.Env = append(os.Environ(),
		codexStdoutHelperEnv+"="+mode,
		"LOGIRA_TEST_CODEX_STDOUT_COUNT="+strconv.Itoa(count),
		"LOGIRA_TEST_CODEX_EXIT_CODE="+strconv.Itoa(exitCode),
	)
	return cmd
}

func codexJSONLFixture(count int) []byte {
	var out bytes.Buffer
	for i := 0; i < count; i++ {
		_, _ = fmt.Fprintf(&out, "{\"type\":\"item.completed\",\"item\":{\"id\":\"item_%04d\",\"type\":\"agent_message\",\"text\":\"record %04d\"}}\n", i, i)
	}
	return out.Bytes()
}
