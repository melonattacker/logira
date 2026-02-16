//go:build linux

package logirad

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/melonattacker/logira/internal/ipc"
)

type Server struct {
	sockPath string

	mu       sync.Mutex
	sessions *SessionManager

	ln *net.UnixListener
}

func NewServer(sockPath string, sessions *SessionManager) *Server {
	return &Server{sockPath: sockPath, sessions: sessions}
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	if strings.TrimSpace(s.sockPath) == "" {
		s.sockPath = ipc.DefaultSockPath
	}
	_ = os.Remove(s.sockPath)
	if err := os.MkdirAll(filepath.Dir(s.sockPath), 0o755); err != nil {
		return err
	}

	addr := &net.UnixAddr{Name: s.sockPath, Net: "unix"}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	_ = os.Chmod(s.sockPath, 0o666)

	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			select {
			case errCh <- err:
			default:
			}
			continue
		}
		go s.handleConn(ctx, c)
	}
}

func (s *Server) handleConn(ctx context.Context, c *net.UnixConn) {
	defer c.Close()

	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	cred, err := ipc.GetPeerCred(c)
	if err != nil {
		_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("peercred: %v", err)))
		return
	}

	r := bufio.NewReaderSize(c, 1<<20)
	line, err := r.ReadBytes('\n')
	if err != nil {
		_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("read: %v", err)))
		return
	}
	typ, err := ipc.DecodeType(line)
	if err != nil {
		_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("decode type: %v", err)))
		return
	}

	switch typ {
	case ipc.MsgTypeStartRun:
		var req ipc.StartRunRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("decode start_run: %v", err)))
			return
		}
		resp, err := s.sessions.StartRun(ctx, cred, req)
		if err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("%v", err)))
			return
		}
		_, _ = c.Write(ipc.MustLine(resp))
	case ipc.MsgTypeStopRun:
		var req ipc.StopRunRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("decode stop_run: %v", err)))
			return
		}
		if err := s.sessions.StopRun(ctx, cred, strings.TrimSpace(req.SessionID), req.ExitCode); err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("%v", err)))
			return
		}
		_, _ = c.Write(ipc.MustLine(ipc.OKResponse{Type: ipc.MsgTypeOK}))
	case ipc.MsgTypeAttachPID:
		var req ipc.AttachPIDRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("decode attach_pid: %v", err)))
			return
		}
		if err := s.sessions.AttachPID(ctx, cred, strings.TrimSpace(req.SessionID), req.PID); err != nil {
			_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("%v", err)))
			return
		}
		_, _ = c.Write(ipc.MustLine(ipc.OKResponse{Type: ipc.MsgTypeOK}))
	default:
		_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("unknown message type %q", typ)))
	}
}
