package ipc

import (
	"context"
	"fmt"
)

// MethodName is the IPC method identifier. Only the 5 values in the
// compile-time allow-list are valid.
type MethodName string

const (
	MethodHealth             MethodName = "Health"
	MethodMintBootstrapToken MethodName = "MintBootstrapToken"
	MethodSubscribeEvents    MethodName = "SubscribeEvents"
	MethodShutdown           MethodName = "Shutdown"
	MethodOpenSystemBrowser  MethodName = "OpenSystemBrowser"
)

// allowedMethods is the compile-time allow-list of IPC method names.
// A CI lint verifies this map has exactly 5 entries and no others.
var allowedMethods = map[MethodName]struct{}{
	MethodHealth:             {},
	MethodMintBootstrapToken: {},
	MethodSubscribeEvents:    {},
	MethodShutdown:           {},
	MethodOpenSystemBrowser:  {},
}

// Request is a generic IPC request frame.
type Request struct {
	Method MethodName `cbor:"method"`
	Params any        `cbor:"params,omitempty"`
}

// Response is a generic IPC response frame.
type Response struct {
	Result any    `cbor:"result,omitempty"`
	Error  string `cbor:"error,omitempty"`
}

// HandlerFunc is an IPC method handler.
// The ctx is cancelled when the server shuts down.
// req is the decoded request params; the handler writes the response to the
// FrameWriter (for streaming handlers like SubscribeEvents).
type HandlerFunc func(ctx context.Context, params any, fw *FrameWriter) (any, error)

// MethodRegistry maps method names to their handler implementations.
// Only names in allowedMethods may be registered.
type MethodRegistry struct {
	handlers map[MethodName]HandlerFunc
}

// NewMethodRegistry creates an empty registry.
func NewMethodRegistry() *MethodRegistry {
	return &MethodRegistry{handlers: make(map[MethodName]HandlerFunc)}
}

// Register adds a handler for name. Panics if name is not in the allow-list
// (compile-time enforcement). This panic is intentional: an
// unregistered method name is a programming error, not a runtime error.
func (r *MethodRegistry) Register(name MethodName, fn HandlerFunc) {
	if _, ok := allowedMethods[name]; !ok {
		panic(fmt.Sprintf("ipc: attempt to register disallowed method %q", name))
	}
	r.handlers[name] = fn
}

// Dispatch finds and calls the handler for req.Method.
// Returns {"error":"unsupported_method"} for names not in the allow-list
// (even if they would otherwise be valid strings).
func (r *MethodRegistry) Dispatch(ctx context.Context, req Request, fw *FrameWriter) Response {
	if _, ok := allowedMethods[req.Method]; !ok {
		// Audit hook placeholder — wired to the audit system.
		return Response{Error: "unsupported_method"}
	}
	fn, registered := r.handlers[req.Method]
	if !registered {
		return Response{Error: "unsupported_method"}
	}
	result, err := fn(ctx, req.Params, fw)
	if err != nil {
		// Do not expose internal error detail through IPC.
		return Response{Error: "internal_error"}
	}
	return Response{Result: result}
}
