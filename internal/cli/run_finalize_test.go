//go:build linux

package cli

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melonattacker/logira/internal/ipc"
)

func TestStopRetryDoesNotHidePersistenceFailure(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	t.Setenv("LOGIRA_SOCK", socket)
	done := make(chan error, 1)
	go func() {
		for _, message := range []string{"persist run: disk full", "unknown session_id"} {
			c, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			_, err = bufio.NewReader(c).ReadBytes('\n')
			if err == nil {
				_, err = c.Write(ipc.MustLine(ipc.ErrorResponse{Type: ipc.MsgTypeError, Message: message}))
			}
			_ = c.Close()
			if err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	client, err := ipc.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	err = stopRunWithRetry(client, "s", 0)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("persistence failure hidden: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
