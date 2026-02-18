//go:build linux

package logirad

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

	cfg ServerConfig

	mu       sync.Mutex
	sessions *SessionManager

	ln *net.UnixListener
}

type ServerConfig struct {
	EnableExec bool
	EnableFile bool
	EnableNet  bool
}

func NewServer(sockPath string, sessions *SessionManager, cfg ServerConfig) *Server {
	return &Server{sockPath: sockPath, sessions: sessions, cfg: cfg}
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

	r := bufio.NewReaderSize(c, 32<<10)
	line, err := readLineLimited(r, 1<<20) // 1 MiB cap
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
	case ipc.MsgTypeStatus:
		// No request fields beyond type.
		resp := ipc.StatusResponse{
			Type:       ipc.MsgTypeStatusOK,
			PID:        os.Getpid(),
			UID:        os.Geteuid(),
			GID:        os.Getegid(),
			EnableExec: s.cfg.EnableExec,
			EnableFile: s.cfg.EnableFile,
			EnableNet:  s.cfg.EnableNet,
		}
		_, _ = c.Write(ipc.MustLine(resp))
	default:
		_, _ = c.Write(ipc.MustLine(ipc.NewErrorf("unknown message type %q", typ)))
	}
}

func readLineLimited(r *bufio.Reader, max int) ([]byte, error) {
	if max <= 0 {
		return nil, fmt.Errorf("invalid max %d", max)
	}
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		out = append(out, frag...)
		if len(out) > max {
			return nil, fmt.Errorf("message too large (>%d bytes)", max)
		}
		if err == nil {
			return out, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}
