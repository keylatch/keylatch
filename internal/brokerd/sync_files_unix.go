//go:build unix

package brokerd

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// receiveFiles reads one message carrying n descriptors from conn.
func receiveFiles(conn *net.UnixConn, n int) ([]*os.File, error) {
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4*n))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return nil, fmt.Errorf("receive descriptors: %w", err)
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	var fds []int
	for i := range msgs {
		rights, err := syscall.ParseUnixRights(&msgs[i])
		if err != nil {
			continue
		}
		fds = append(fds, rights...)
	}
	if len(fds) != n {
		for _, fd := range fds {
			_ = syscall.Close(fd)
		}
		return nil, errors.New("the client sent the wrong number of descriptors")
	}
	files := make([]*os.File, n)
	for i, fd := range fds {
		syscall.CloseOnExec(fd)
		files[i] = os.NewFile(uintptr(fd), fmt.Sprintf("sync-fd-%d", i)) //nolint:gosec // G115: a descriptor is a small non-negative int
	}
	return files, nil
}
