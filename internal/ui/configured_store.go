package ui

import (
	"context"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	_ "github.com/keylatch/keylatch/internal/backend/all"
	"github.com/keylatch/keylatch/internal/backend/dispatch"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// configuredStore resolves configuration on each operation, so first-run setup
// and recovery from a locked backend do not require restarting the desktop app.
// Access is serialized and each backend is closed to release backend resources.
type configuredStore struct {
	mu  sync.Mutex
	env llmcontext.Lookup
}

func (s *configuredStore) open(ctx context.Context) (backend.Backend, error) {
	cfg, err := config.Load(paths.Config(s.env))
	if err != nil {
		return nil, err
	}
	return dispatch.Open(ctx, cfg, s.env)
}
func (s *configuredStore) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.open(ctx)
	if err != nil {
		return nil, backend.Meta{}, err
	}
	defer b.Close() //nolint:errcheck
	value, meta, err := b.Get(ctx, path)
	// A backend may zero its own buffers during Close; return a caller-owned copy.
	result := append([]byte(nil), value...)
	for i := range value {
		value[i] = 0
	}
	return result, meta, err
}
func (s *configuredStore) Set(ctx context.Context, path string, value []byte, meta backend.Meta) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer b.Close() //nolint:errcheck
	return b.Set(ctx, path, value, meta)
}
func (s *configuredStore) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.open(ctx)
	if err != nil {
		return nil, err
	}
	defer b.Close() //nolint:errcheck
	return b.List(ctx, prefix)
}
func (s *configuredStore) Delete(ctx context.Context, path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := s.open(ctx)
	if err != nil {
		return err
	}
	defer b.Close() //nolint:errcheck
	return b.Delete(ctx, path)
}
