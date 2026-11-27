package contained

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openPTY returns a pseudo-terminal pair sized to ws.
func openPTY(ws Winsize) (master, slave *os.File, err error) {
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("contained: open /dev/ptmx: %w", err)
	}
	fail := func(err error) (*os.File, *os.File, error) {
		_ = master.Close()
		return nil, nil, fmt.Errorf("contained: open pty: %w", err)
	}
	fd := int(master.Fd()) //nolint:gosec // G115: a descriptor fits in int
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		return fail(err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		return fail(err)
	}
	slave, err = os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return fail(err)
	}
	if err := setWinsize(master, ws); err != nil {
		_ = slave.Close()
		return fail(err)
	}
	return master, slave, nil
}

func setWinsize(f *os.File, ws Winsize) error {
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols}) //nolint:gosec // G115: a descriptor fits in int
}

// ptyReader reports the end of a PTY master as EOF: reading it after the last
// slave closes fails with EIO. It owns the master and closes it at the end.
type ptyReader struct{ f *os.File }

func (r ptyReader) Read(p []byte) (int, error) {
	n, err := r.f.Read(p)
	if errors.Is(err, unix.EIO) {
		_ = r.f.Close()
		return n, io.EOF
	}
	return n, err
}

func (r ptyReader) Close() error { return r.f.Close() }

// keepOpen stops Close from hanging up the terminal: the client ends a
// terminal session with its own end-of-file key.
type keepOpen struct{ f *os.File }

func (k keepOpen) Write(p []byte) (int, error) { return k.f.Write(p) }
func (keepOpen) Close() error                  { return nil }
