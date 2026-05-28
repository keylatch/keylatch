package cli

import (
	"context"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// dispatchedStore adapts a backend.Backend to the connections.Store interface.
// It selects the backend via dispatch.Select on each call.
//
// T-04-01 audit: dispatchedStore.Get is the central value-bearing read path for
// all CLI commands. Every caller that reads a credential value via this method
// must be gated by one of:
//
//	(a) llmcontext.IsLLMSession guard (blocks in LLM sessions — S-INV-2)
//	(b) AsValueBearing wrapper (wraps the Cobra RunE with GuardLLMSession)
//	(c) provably unreachable in LLM sessions (e.g. bootstrap, keyring init
//	    which require a terminal and cannot be invoked by an agent)
//
// Current callers and their guard status:
//   - connections.Test  → cmd_status.go:newPhase3TestCmd  → (a) IsLLMSession guard added (T-04-01)
//   - connections.Test  → cmd_connect.go                  → (a) connect is blocked in LLM sessions via S-INV-6
//   - connections.RunTestStrategy → cmd_connect.go        → same
//   - validate.CheckField → cmd_connect.go               → same (connect blocked)
//   - connections.Store.Get in proxy/server.go           → (c) proxy server; the gateway_proxy driver
//     starts the proxy in the parent CLI process, not the child; the parent process must already
//     have passed the LLM guard in DispatchRunner.Run before arriving here
//
// Any new callers MUST add a guard. If the call site is not value-bearing
// (e.g. reading metadata), prefer backend.GetMeta over backend.Get.
type dispatchedStore struct {
	cfg config.Config
	env llmcontext.Lookup
}

func newDispatchedStore(cfg config.Config, env llmcontext.Lookup) *dispatchedStore {
	return &dispatchedStore{cfg: cfg, env: env}
}

func (s *dispatchedStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	return b.Get(ctx, path)
}

func (s *dispatchedStore) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return err
	}
	return b.Set(ctx, path, value, meta)
}

func (s *dispatchedStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return nil, err
	}
	return b.List(ctx, prefix)
}

func (s *dispatchedStore) Delete(ctx context.Context, path string) error {
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return err
	}
	return b.Delete(ctx, path)
}
