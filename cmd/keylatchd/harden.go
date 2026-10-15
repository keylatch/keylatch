package main

import (
	"log/slog"

	"github.com/keylatch/keylatch/internal/proc"
)

// hardenProcess keeps other processes of the same user from reading the
// daemon's memory and environment, which hold unwrapped keys.
func hardenProcess() {
	if err := proc.Harden(); err != nil {
		slog.Warn("process hardening incomplete", "error", err)
	}
}
