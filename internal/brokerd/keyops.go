package brokerd

import (
	"context"
	"fmt"

	"github.com/keylatch/keylatch/internal/backend/brokerstore"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/presence"
)

type partitionKeys struct{ store *brokerstore.Store }

func (p partitionKeys) Fetch(ctx context.Context, path string) ([]byte, error) {
	value, _, err := p.store.Get(ctx, path)
	return value, err
}

func (s *Server) keyService(p *partition) (*keyops.Service, *keyops.Admin, error) {
	mac, err := s.cfg.Keys.KeyPolicyKeyFor(uidString(p.uid))
	if err != nil {
		return nil, nil, err
	}
	policy := keyops.NewStore(paths.KeyOperations(p.env), mac)
	service, err := keyops.New(policy, partitionKeys{p.store}, s.cfg.Audit)
	if err != nil {
		clear(mac)
		return nil, nil, err
	}
	admin, err := keyops.NewAdmin(policy, s.cfg.Audit)
	if err != nil {
		clear(mac)
		return nil, nil, err
	}
	return service, admin, nil
}

func (s *Server) keyPresence(uid uint32) func(context.Context, control.Peer, presence.Action, string) error {
	return func(ctx context.Context, peer control.Peer, action presence.Action, summary string) error {
		if peer.UID != uid || peer.PID <= 0 || peer.Start == "" {
			return fmt.Errorf("%w: peer does not belong to this partition", ErrPresenceUnavailable)
		}
		if s.presence == nil || s.presence.Method == nil {
			return ErrPresenceUnavailable
		}
		if !s.presence.claim(uid) {
			return ErrPromptOpen
		}
		defer s.presence.release(uid)
		return s.presence.Method.Verify(ctx, Subject{UID: uid, PID: peer.PID, Start: peer.Start}, string(action), summary)
	}
}
