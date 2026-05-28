package cli

import (
	"context"
	"io"

	"github.com/keylatch/keylatch/internal/llmcontext"
)

// Handler is a function that processes a CLI command.
type Handler func(ctx context.Context, args HandlerArgs) (Result, error)

// HandlerArgs carries all inputs a handler needs, including I/O streams and env access.
type HandlerArgs struct {
	Positional []string
	Flags      map[string]string
	Env        llmcontext.Lookup
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
}

// Result carries the outcome of a handler invocation.
type Result struct {
	ExitCode int
	Message  string
	JSON     any
}
