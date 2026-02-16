//go:build linux

package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const DefaultSockPath = "/run/logira.sock"

func SockPath() string {
	if v := strings.TrimSpace(os.Getenv("LOGIRA_SOCK")); v != "" {
		return v
	}
	return DefaultSockPath
}

type Client struct {
	conn *net.UnixConn
	r    *bufio.Reader
}

func Dial(ctx context.Context) (*Client, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	addr := &net.UnixAddr{Name: SockPath(), Net: "unix"}
	c, err := d.DialContext(ctx, "unix", addr.Name)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr.Name, err)
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		return nil, fmt.Errorf("unexpected conn type %T", c)
	}
	return &Client{conn: uc, r: bufio.NewReaderSize(uc, 1<<20)}, nil
}

func (c *Client) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *Client) roundTrip(ctx context.Context, req any, resp any) error {
	if c.conn == nil {
		return fmt.Errorf("client closed")
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	} else {
		_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	if _, err := c.conn.Write(MustLine(req)); err != nil {
		return err
	}
	line, err := c.r.ReadBytes('\n')
	if err != nil {
		return err
	}
	typ, err := DecodeType(line)
	if err != nil {
		return err
	}
	if typ == MsgTypeError {
		var er ErrorResponse
		_ = json.Unmarshal(line, &er)
		return fmt.Errorf("logirad error: %s", strings.TrimSpace(er.Message))
	}
	if err := json.Unmarshal(line, resp); err != nil {
		return err
	}
	return nil
}

func (c *Client) StartRun(ctx context.Context, r StartRunRequest) (StartRunResponse, error) {
	r.Type = MsgTypeStartRun
	var resp StartRunResponse
	err := c.roundTrip(ctx, r, &resp)
	return resp, err
}

func (c *Client) StopRun(ctx context.Context, sessionID string, exitCode int) error {
	req := StopRunRequest{Type: MsgTypeStopRun, SessionID: sessionID, ExitCode: exitCode}
	var resp OKResponse
	if err := c.roundTrip(ctx, req, &resp); err != nil {
		return err
	}
	if strings.TrimSpace(resp.Type) != MsgTypeOK {
		return fmt.Errorf("unexpected response type %q", resp.Type)
	}
	return nil
}

func (c *Client) AttachPID(ctx context.Context, sessionID string, pid int) error {
	req := AttachPIDRequest{Type: MsgTypeAttachPID, SessionID: sessionID, PID: pid}
	var resp OKResponse
	if err := c.roundTrip(ctx, req, &resp); err != nil {
		return err
	}
	if strings.TrimSpace(resp.Type) != MsgTypeOK {
		return fmt.Errorf("unexpected response type %q", resp.Type)
	}
	return nil
}
