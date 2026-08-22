//go:build linux && integration

package nettrace

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/melonattacker/logira/internal/model"
)

func TestKnownPortIPv4AndIPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for eBPF integration test")
	}
	tracer := NewTracer()
	events, err := tracer.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var got []model.NetDetail
	done := make(chan struct{})
	go func() {
		defer close(done)
		for event := range events {
			var detail model.NetDetail
			if json.Unmarshal(event.Detail, &detail) == nil && detail.PID == os.Getpid() {
				mu.Lock()
				got = append(got, detail)
				mu.Unlock()
			}
		}
	}()

	runTCPExchange(t, "tcp4", "127.0.0.1:18080")
	runUDPConnectProbe(t, 65535)
	ipv6Ran := true
	if err := tryTCPExchange("tcp6", "[::1]:18080"); err != nil {
		ipv6Ran = false
		t.Logf("IPv6 loopback unavailable: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := tracer.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-done

	mu.Lock()
	defer mu.Unlock()
	assertKnownPort(t, got, "127.0.0.1", 18080)
	assertUDPProbe(t, got, "127.0.0.1", 65535)
	if ipv6Ran {
		assertKnownPort(t, got, "::1", 18080)
	}
	for _, detail := range got {
		if detail.Proto == "tcp" && (detail.DstIP == "127.0.0.1" || detail.DstIP == "::1") && detail.DstPort != 0 && detail.DstPort != 18080 {
			t.Fatalf("corrupted localhost port: %+v", detail)
		}
		if detail.Bytes < 0 || detail.Bytes > 1<<20 {
			t.Fatalf("unrealistic byte count: %+v", detail)
		}
	}
}

func runTCPExchange(t *testing.T, network, address string) {
	t.Helper()
	if err := tryTCPExchange(network, address); err != nil {
		t.Fatal(err)
	}
}

func tryTCPExchange(network, address string) error {
	listener, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			serverDone <- err
			return
		}
		_, err = conn.Write([]byte("ok"))
		serverDone <- err
	}()

	clientErr := rawTCPExchange(network)
	serverErr := <-serverDone
	if clientErr != nil {
		return clientErr
	}
	return serverErr
}

func rawTCPExchange(network string) error {
	family := unix.AF_INET
	var destination unix.Sockaddr = &unix.SockaddrInet4{Port: 18080, Addr: [4]byte{127, 0, 0, 1}}
	if network == "tcp6" {
		family = unix.AF_INET6
		destination = &unix.SockaddrInet6{Port: 18080, Addr: [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}
	}
	fd, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, destination); err != nil {
		return err
	}
	if err := unix.Sendto(fd, []byte("ping"), 0, nil); err != nil {
		return err
	}
	response := make([]byte, 2)
	_, _, err = unix.Recvfrom(fd, response, 0)
	return err
}

func runUDPConnectProbe(t *testing.T, port int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := unix.Connect(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
}

func assertKnownPort(t *testing.T, events []model.NetDetail, ip string, port uint16) {
	t.Helper()
	seenConnect, seenBytes := false, false
	for _, detail := range events {
		if detail.DstIP != ip || detail.DstPort != port {
			continue
		}
		if detail.Op == "connect" && detail.Proto == "tcp" && (detail.ConnectState == "completed" || detail.ConnectState == "in_progress") {
			seenConnect = true
		}
		if (detail.Op == "send" || detail.Op == "recv") && detail.Proto == "tcp" && detail.Bytes > 0 {
			seenBytes = true
		}
	}
	if !seenConnect || !seenBytes {
		t.Fatalf("known endpoint %s:%d missing connect/bytes; events=%+v", ip, port, events)
	}
}

func assertUDPProbe(t *testing.T, events []model.NetDetail, ip string, port uint16) {
	t.Helper()
	for _, detail := range events {
		if detail.Op == "connect" && detail.Proto == "udp" && detail.DstIP == ip && detail.DstPort == port && detail.ConnectState == "completed" {
			return
		}
	}
	t.Fatalf("UDP probe %s:%d was not structurally identified; events=%+v", ip, port, events)
}
