package gpgcard_test

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/trust/gpgcard"
)

// mockAssuanServer starts a minimal Assuan-protocol mock server on a Unix socket.
func mockAssuanServer(t *testing.T, sockPath string, pksignResp string) (stop func()) {
	t.Helper()
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("mock assuan listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockAssuan(conn, pksignResp)
		}
	}()

	return func() {
		ln.Close()
		os.Remove(sockPath)
	}
}

func handleMockAssuan(conn net.Conn, pksignResp string) {
	defer conn.Close()
	fmt.Fprintf(conn, "OK Keylatch mock scdaemon ready\n")

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		cmd := strings.TrimRight(string(buf[:n]), "\r\n ")
		switch {
		case strings.HasPrefix(cmd, "SETKEY"), strings.HasPrefix(cmd, "SIGKEY"), strings.HasPrefix(cmd, "SETHASH"):
			fmt.Fprintf(conn, "OK\n")
		case strings.HasPrefix(cmd, "PKSIGN"):
			if pksignResp != "" {
				fmt.Fprintf(conn, "D %s\n", pksignResp)
			}
			fmt.Fprintf(conn, "OK\n")
		case strings.HasPrefix(cmd, "BYE"):
			fmt.Fprintf(conn, "OK closing connection\n")
			return
		default:
			fmt.Fprintf(conn, "ERR 67108949 Unknown command\n")
		}
	}
}

func testSockPath(name string) string {
	return filepath.Join("/tmp", fmt.Sprintf("kl-%s-%d.sock", name, os.Getpid()))
}

func TestAssuanDial_MockServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets with /tmp paths are not supported on Windows")
	}
	sockPath := testSockPath("assuan-dial")
	stop := mockAssuanServer(t, sockPath, "deadbeef")
	defer stop()

	conn, err := gpgcard.AssuanDial(sockPath)
	if err != nil {
		t.Fatalf("AssuanDial: %v", err)
	}
	defer conn.Close()
}

func TestAssuanSign_MockServer(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets with /tmp paths are not supported on Windows")
	}
	sockPath := testSockPath("assuan-sign")
	fixedResp := "cafebabe"
	stop := mockAssuanServer(t, sockPath, fixedResp)
	defer stop()

	conn, err := gpgcard.AssuanDial(sockPath)
	if err != nil {
		t.Fatalf("AssuanDial: %v", err)
	}
	defer conn.Close()

	data := make([]byte, 32)
	sig, err := gpgcard.AssuanSign(conn, "DEADBEEF01020304", data)
	if err != nil {
		t.Fatalf("AssuanSign: %v", err)
	}
	if len(sig) == 0 {
		t.Error("AssuanSign returned empty signature")
	}
}

func TestAssuanDial_CardNotPresent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets are not supported on Windows")
	}
	_, err := gpgcard.AssuanDial("/nonexistent/scdaemon.socket")
	if err == nil {
		t.Error("expected error for non-existent socket, got nil")
	}
}
