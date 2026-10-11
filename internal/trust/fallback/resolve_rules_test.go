package fallback_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/fallback"
)

type trClosingRoot struct {
	stubRoot
	closes *atomic.Int32
}

func (r *trClosingRoot) Close() error { r.closes.Add(1); return nil }

func trRegisterClosing(t *testing.T, rt trust.RootType, launchdSafe bool, closes *atomic.Int32) {
	t.Helper()
	trust.Register(rt, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		return &trClosingRoot{stubRoot: stubRoot{id: spec.ID, kind: rt, launchdSafe: launchdSafe}, closes: closes}, nil
	})
	t.Cleanup(func() { trust.Unregister(rt) })
}

func trReasons(r fallback.Reason) []fallback.SkipReason {
	out := make([]fallback.SkipReason, 0, len(r.Skipped))
	for _, s := range r.Skipped {
		out = append(out, s.Reason)
	}
	return out
}

func TestResolveSkipsTypesWithoutCapability(t *testing.T) {
	registerMock(t, trust.RootPassphrase)
	registerMock(t, trust.RootSSHAgent)
	chain := fallback.NewChain([]trust.RootSpec{
		{ID: "pp", Type: trust.RootPassphrase, Status: trust.RootActive},
		{ID: "ssh", Type: trust.RootSSHAgent, Status: trust.RootActive},
	})
	root, reason, err := chain.Resolve(context.Background(), fallback.Operation{
		Kind: fallback.OperationSign, Capability: "sign_challenge", InteractiveAllowed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if root.ID() != "ssh" {
		t.Fatalf("root = %q", root.ID())
	}
	if len(reason.Skipped) != 1 || reason.Skipped[0].Reason != fallback.SkipCapability || reason.Skipped[0].Detail != "sign_challenge" {
		t.Fatalf("skipped = %+v", reason.Skipped)
	}
}

func TestResolveExhaustReasons(t *testing.T) {
	_, reason, err := fallback.NewChain(nil).Resolve(context.Background(), fallback.Operation{})
	if !errors.Is(err, trust.ErrChainExhausted) || reason.ExhaustReason != "no roots configured" {
		t.Fatalf("empty chain: err=%v reason=%q", err, reason.ExhaustReason)
	}

	var closes atomic.Int32
	trRegisterClosing(t, "tr_fb_unsafe", false, &closes)
	_, reason, err = fallback.NewChain([]trust.RootSpec{
		{ID: "u1", Type: "tr_fb_unsafe", Status: trust.RootActive},
		{ID: "r1", Type: "tr_fb_unsafe", Status: trust.RootRevoked},
	}).Resolve(context.Background(), fallback.Operation{Kind: fallback.OperationUnwrap})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Fatalf("err = %v", err)
	}
	if reason.ExhaustReason != "all 2 root(s) skipped: u1(not_launchd_safe), r1(not_active)" {
		t.Fatalf("ExhaustReason = %q", reason.ExhaustReason)
	}
	if closes.Load() != 1 {
		t.Fatalf("launchd-unsafe root closed %d times, want 1", closes.Load())
	}
}

func TestResolveAllWithoutRequiredIDsUsesResolve(t *testing.T) {
	registerMock(t, "tr_fb_one")
	chain := fallback.NewChain([]trust.RootSpec{{ID: "one", Type: "tr_fb_one", Status: trust.RootActive}})
	roots, _, err := chain.ResolveAll(context.Background(), fallback.Operation{InteractiveAllowed: true})
	if err != nil || len(roots) != 1 || roots[0].ID() != "one" {
		t.Fatalf("roots=%v err=%v", roots, err)
	}

	_, _, err = fallback.NewChain(nil).ResolveAll(context.Background(), fallback.Operation{})
	if !errors.Is(err, trust.ErrChainExhausted) {
		t.Fatalf("empty: err = %v", err)
	}
}

func TestResolveAllSkipRulesAndCleanup(t *testing.T) {
	var closes atomic.Int32
	trRegisterClosing(t, "tr_fb_ok", true, &closes)
	registerMock(t, trust.RootPassphrase)
	registerMock(t, trust.RootFIDO2)
	registerFailing(t, "tr_fb_broken")

	chain := fallback.NewChain([]trust.RootSpec{
		{ID: "ok", Type: "tr_fb_ok", Status: trust.RootActive},
		{ID: "retired", Type: "tr_fb_ok", Status: trust.RootRetired},
		{ID: "pp", Type: trust.RootPassphrase, Status: trust.RootActive},
		{ID: "fido", Type: trust.RootFIDO2, Status: trust.RootActive},
		{ID: "broken", Type: "tr_fb_broken", Status: trust.RootActive},
	})
	cases := []struct {
		id         string
		op         fallback.Operation
		wantReason fallback.SkipReason
	}{
		{"retired", fallback.Operation{}, fallback.SkipNotActive},
		{"pp", fallback.Operation{Capability: "sign"}, fallback.SkipCapability},
		{"fido", fallback.Operation{LLMSession: true}, fallback.SkipLLMPresence},
		{"broken", fallback.Operation{}, fallback.SkipConstructFailed},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			before := closes.Load()
			op := tc.op
			op.RequireAllOfRootIDs = []string{"ok", tc.id}
			roots, reason, err := chain.ResolveAll(context.Background(), op)
			if !errors.Is(err, trust.ErrChainExhausted) || !strings.Contains(err.Error(), `required root "`+tc.id+`" missing`) {
				t.Fatalf("err = %v", err)
			}
			if roots != nil {
				t.Fatalf("roots = %v", roots)
			}
			if got := trReasons(reason); len(got) != 1 || got[0] != tc.wantReason {
				t.Fatalf("reasons = %v, want [%s]", got, tc.wantReason)
			}
			if reason.ExhaustReason != `required root "`+tc.id+`" not available` {
				t.Fatalf("ExhaustReason = %q", reason.ExhaustReason)
			}
			if closes.Load() != before+1 {
				t.Fatal("already-opened root was not closed on failure")
			}
		})
	}
}

func TestResolveAllMatchesByTypeName(t *testing.T) {
	registerMock(t, "tr_fb_typed")
	registerMock(t, "tr_fb_other")
	chain := fallback.NewChain([]trust.RootSpec{
		{ID: "x1", Type: "tr_fb_other", Status: trust.RootActive},
		{ID: "t1", Type: "tr_fb_typed", Status: trust.RootActive},
	})
	roots, reason, err := chain.ResolveAll(context.Background(), fallback.Operation{
		RequireAllOfRootIDs: []string{"tr_fb_typed", "x1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 || roots[0].ID() != "t1" || roots[1].ID() != "x1" || len(reason.Skipped) != 0 {
		t.Fatalf("roots = %v skipped = %+v", roots, reason.Skipped)
	}
}
