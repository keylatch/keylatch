//go:build test

package runner

import (
	"context"
	"strings"
)

// StubRunner is a test-only implementation of Runner.
// It checks the command prefix against Connection.AllowedCommandPrefixes
// and returns ErrCommandNotAllowed if no prefix matches.
type StubRunner struct{}

// Run implements Runner for StubRunner.
// Returns ErrCommandNotAllowed when no prefix in conn.AllowedCommandPrefixes matches.
func (s StubRunner) Run(_ context.Context, conn Connection, command []string, _ RunOptions) (Receipt, error) {
	if len(conn.AllowedCommandPrefixes) == 0 {
		return Receipt{}, ErrCommandNotAllowed
	}
	cmd := strings.Join(command, " ")
	for _, prefix := range conn.AllowedCommandPrefixes {
		if strings.HasPrefix(cmd, prefix) {
			return Receipt{ExitCode: 0}, nil
		}
	}
	return Receipt{}, ErrCommandNotAllowed
}
