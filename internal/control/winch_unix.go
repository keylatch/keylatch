//go:build !windows

package control

import (
	"os"
	"os/signal"
	"syscall"
)

// resizeSignals delivers a value whenever the terminal changes size.
func resizeSignals() <-chan os.Signal {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	return ch
}
