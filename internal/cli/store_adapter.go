package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/childstore"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/registry"
)

// dispatchedStore adapts a backend.Backend to the connections.Store interface.
// It selects the backend via dispatch.Select on each call.
//
// dispatchedStore.Get is the central value-bearing read path for
// all CLI commands. Every caller that reads a credential value via this method
// must be gated by one of:
//
//	(a) llmcontext.IsLLMSession guard (blocks in LLM sessions)
//	(b) AsValueBearing wrapper (wraps the Cobra RunE with GuardLLMSession)
//	(c) provably unreachable in LLM sessions (e.g. bootstrap, keyring init
//	    which require a terminal and cannot be invoked by an agent)
//
// Current callers and their guard status:
//   - connections.Test  → cmd_status.go:newTestCmd         → (a) IsLLMSession guard added
//   - connections.Test  → cmd_connect.go                  → (a) connect is blocked in LLM sessions
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

// CustomTemplates returns the lookup that builds a custom connection's
// template from the binding it stored. It reads the binding and the field
// names only, never a secret value.
func CustomTemplates(env llmcontext.Lookup) func(ctx context.Context, name string) (registry.ConnectionTemplate, error) {
	return func(ctx context.Context, name string) (registry.ConnectionTemplate, error) {
		if !connections.ValidCustomName(name) {
			return registry.ConnectionTemplate{}, registry.ErrNoBinding
		}
		cfg := config.Default()
		if loaded, err := config.Load(paths.Config(env)); err == nil {
			cfg = loaded
		}
		return connections.CustomTemplate(ctx, newDispatchedStore(cfg, env), "", name)
	}
}

func newDispatchedStore(cfg config.Config, env llmcontext.Lookup) *dispatchedStore {
	return &dispatchedStore{cfg: cfg, env: env}
}

// brokerStoreActive reports that stored secrets live in the system broker, so
// this process writes through its operations and cannot read values. A verb
// the broker itself runs for the user reads through its store descriptor and
// is not routed back.
func brokerStoreActive(env llmcontext.Lookup) bool {
	if env == nil {
		env = llmcontext.DefaultLookup
	}
	return env(childstore.EnvFD) == "" && brokerInstalled(env)
}

// errBrokerRead is what a CLI process gets when it asks for a value the broker
// keeps: values are used inside the broker's own verbs, never returned.
var errBrokerRead = fmt.Errorf("%w: the system broker does not return stored values to the CLI; use call, run or mint", backend.ErrLocked)

func (s *dispatchedStore) broker() (brokerCaller, bool, error) {
	if !brokerStoreActive(s.env) {
		return nil, false, nil
	}
	c, err := brokerClient(s.env)
	return c, true, err
}

func (s *dispatchedStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if _, ok, err := s.broker(); ok || err != nil {
		if err == nil {
			err = errBrokerRead
		}
		return nil, backend.Meta{}, err
	}
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	return b.Get(ctx, path)
}

func (s *dispatchedStore) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	if bc, ok, err := s.broker(); ok || err != nil {
		if err != nil {
			return err
		}
		_, err = brokerPrivileged(bc, "set", brokerapi.Request{Op: brokerapi.OpSecretSet, Path: path, Value: value})
		return err
	}
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return err
	}
	return b.Set(ctx, path, value, meta)
}

func (s *dispatchedStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	if bc, ok, err := s.broker(); ok || err != nil {
		if err != nil {
			return nil, err
		}
		resp, err := bc.Call(brokerapi.Request{Op: brokerapi.OpSecretList})
		if err != nil {
			return nil, err
		}
		if !resp.OK {
			return nil, brokerFailure("list", resp)
		}
		var out []backend.Entry
		for _, e := range resp.Entries {
			if strings.HasPrefix(e.Path, prefix) {
				out = append(out, backend.Entry{Meta: backend.Meta{Path: e.Path, Version: e.Version, Backend: "broker"}, Exists: true})
			}
		}
		return out, nil
	}
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return nil, err
	}
	return b.List(ctx, prefix)
}

func (s *dispatchedStore) Delete(ctx context.Context, path string) error {
	if bc, ok, err := s.broker(); ok || err != nil {
		if err != nil {
			return err
		}
		_, err = brokerPrivileged(bc, "delete", brokerapi.Request{Op: brokerapi.OpSecretDelete, Path: path})
		return err
	}
	b, err := dispatch.Select(ctx, s.cfg, s.env)
	if err != nil {
		return err
	}
	return b.Delete(ctx, path)
}
