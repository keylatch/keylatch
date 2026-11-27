//go:build windows

package winpipe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

const openToEveryone = "D:(A;;GA;;;WD)"

func pipeName(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\keylatch-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

func listen(t *testing.T) (*Listener, string) {
	t.Helper()
	name := pipeName(t)
	l, err := Listen(name, openToEveryone)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, name
}

func TestEchoAndClientIdentity(t *testing.T) {
	l, name := listen(t)
	if !Exists(name) {
		t.Fatal("the pipe does not exist after Listen")
	}
	got := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- err
			return
		}
		defer c.Close()
		pid, _, err := c.ClientProcess()
		if err != nil || int(pid) != os.Getpid() {
			got <- fmt.Errorf("client process = %d, %v", pid, err)
			return
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			got <- err
			return
		}
		_, err = c.Write([]byte("echo:" + line))
		got <- err
	}()
	c, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pid, err := c.ServerProcess(); err != nil || int(pid) != os.Getpid() {
		t.Fatalf("server process = %d, %v", pid, err)
	}
	if _, err := c.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	reply, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || reply != "echo:hello\n" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
	if err := <-got; err != nil {
		t.Fatal(err)
	}
}

func TestReadAndWriteDoNotBlockEachOther(t *testing.T) {
	l, name := listen(t)
	srv := make(chan *Conn, 1)
	go func() {
		c, _ := l.Accept()
		srv <- c
	}()
	c, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	s := <-srv
	defer s.Close()

	readDone := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		readDone <- err
	}()
	time.Sleep(50 * time.Millisecond)
	writeDone := make(chan error, 1)
	go func() {
		_, err := c.Write([]byte("x"))
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pending read blocked a write on the same pipe")
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(s, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("server read = %q, %v", buf, err)
	}
	if _, err := s.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
}

func TestDeadlineAndClose(t *testing.T) {
	l, name := listen(t)
	srv := make(chan *Conn, 1)
	go func() {
		c, _ := l.Accept()
		srv <- c
	}()
	c, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := <-srv
	defer s.Close()

	_ = c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read past its deadline = %v", err)
	}
	// Setting a past deadline wakes a read that is already waiting.
	_ = c.SetReadDeadline(time.Time{})
	woke := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		woke <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = c.SetReadDeadline(time.Now())
	select {
	case err := <-woke:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("a woken read = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SetReadDeadline did not wake a pending read")
	}

	// Close cancels a pending read; the peer then reads EOF.
	_ = c.SetReadDeadline(time.Time{})
	go func() {
		_, err := c.Read(make([]byte, 1))
		woke <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = c.Close()
	select {
	case err := <-woke:
		if err == nil {
			t.Fatal("a read on a closed pipe succeeded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not cancel a pending read")
	}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("the peer of a closed pipe = %v", err)
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("a write on a closed pipe succeeded")
	}
}

func TestFirstInstanceCannotBeSquatted(t *testing.T) {
	l, name := listen(t)
	if _, err := Listen(name, openToEveryone); err == nil {
		t.Fatal("a second listener took over the pipe name")
	}
	_ = l.Close()
	if _, err := l.Accept(); err == nil {
		t.Fatal("Accept on a closed listener succeeded")
	}
}

func TestDialMissingPipe(t *testing.T) {
	if Exists(pipeName(t)) {
		t.Fatal("a pipe that was never created exists")
	}
	if _, err := Dial(pipeName(t), 100*time.Millisecond); err == nil {
		t.Fatal("dialing a missing pipe succeeded")
	}
}

func TestAcceptReturnsWhenClosed(t *testing.T) {
	l, _ := listen(t)
	done := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	_ = l.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not release Accept")
	}
}

func TestCloseWriteEndsTheStream(t *testing.T) {
	l, name := listen(t)
	srv := make(chan *Conn, 1)
	go func() {
		c, _ := l.Accept()
		srv <- c
	}()
	c, err := Dial(name, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s := <-srv
	defer s.Close()
	go func() {
		_, _ = s.Write([]byte("bye"))
		_ = s.CloseWrite()
	}()
	b, err := io.ReadAll(c)
	if err != nil || string(b) != "bye" {
		t.Fatalf("stream = %q, %v", b, err)
	}
}
