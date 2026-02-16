//go:build linux

package ipc

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

type PeerCred struct {
	PID int
	UID int
	GID int
}

func GetPeerCred(conn *net.UnixConn) (PeerCred, error) {
	var out PeerCred
	rc, err := conn.SyscallConn()
	if err != nil {
		return out, err
	}
	var ucred *unix.Ucred
	var serr error
	if err := rc.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			serr = e
			return
		}
		ucred = u
	}); err != nil {
		return out, err
	}
	if serr != nil {
		return out, serr
	}
	if ucred == nil {
		return out, fmt.Errorf("peercred unavailable")
	}
	out.PID = int(ucred.Pid)
	out.UID = int(ucred.Uid)
	out.GID = int(ucred.Gid)
	return out, nil
}
