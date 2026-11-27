package broker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
)

type scEmitter struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (e *scEmitter) Emit(_ context.Context, ev audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	return e.err
}

func (e *scEmitter) byAction(a audit.Action) []audit.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []audit.Event
	for _, ev := range e.events {
		if ev.Action == a {
			out = append(out, ev)
		}
	}
	return out
}

type scFailStrategy struct{ err error }

func (s scFailStrategy) Provider() string { return "failing" }
func (s scFailStrategy) Exchange(context.Context, string, string, string) (ExchangeResult, error) {
	return ExchangeResult{}, s.err
}

func scBroker(t *testing.T, em audit.Emitter) *BrokerImpl {
	t.Helper()
	t.Cleanup(ResetInProcessSingleton)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	strategies := map[string]ExchangeStrategy{
		"prov-a":  &mockStrategy{provider: "prov-a", token: []byte("tok-a"), ttl: time.Hour},
		"prov-b":  &mockStrategy{provider: "prov-b", token: []byte("tok-b"), ttl: time.Hour},
		"failing": scFailStrategy{err: errors.New("upstream down")},
	}
	return NewBroker(ctx, strategies, em, []byte("sc-hmac-key-0123456789abcdef0123"))
}

func TestExchange_UnknownAndFailingStrategies(t *testing.T) {
	b := scBroker(t, &scEmitter{})
	if _, err := b.Exchange(context.Background(), "a", "s", "nope", "c", "n"); !errors.Is(err, ErrUnsupportedExchange) {
		t.Fatalf("unknown provider: %v", err)
	}
	if _, err := b.Exchange(context.Background(), "a", "s", "failing", "c", "n"); err == nil || !strings.Contains(err.Error(), "upstream down") {
		t.Fatalf("failing strategy: %v", err)
	}
	if b.cache.size() != 0 {
		t.Fatal("failed exchange was cached")
	}
}

func TestExchangeResult_TokenBytesIsCopyAndZero(t *testing.T) {
	b := scBroker(t, &scEmitter{})
	res, err := b.Exchange(context.Background(), "a", "s", "prov-a", "c", "n")
	if err != nil {
		t.Fatal(err)
	}
	cp := res.TokenBytes()
	if string(cp) != "tok-a" {
		t.Fatalf("TokenBytes = %q", cp)
	}
	cp[0] = 'X'
	if string(res.TokenBytes()) != "tok-a" {
		t.Fatal("TokenBytes exposed internal buffer")
	}
	hit, err := b.Exchange(context.Background(), "a", "s", "prov-a", "c", "n")
	if err != nil || hit.ExchangeType != CacheHit {
		t.Fatalf("cache hit: %+v %v", hit, err)
	}
	hit.Zero()
	if string(hit.TokenBytes()) != "\x00\x00\x00\x00\x00" {
		t.Fatalf("Zero left %q", hit.TokenBytes())
	}
	again, err := b.Exchange(context.Background(), "a", "s", "prov-a", "c", "n")
	if err != nil || string(again.TokenBytes()) != "tok-a" {
		t.Fatal("zeroing a cache-hit result corrupted the cached token")
	}
}

func TestHashID_NoKeyDoesNotLeakID(t *testing.T) {
	if got := hashID(nil, "alice@example.com"); got != "no-hmac-key" {
		t.Fatalf("hashID without key = %q", got)
	}
	a := hashID([]byte("k1"), "alice")
	if a == hashID([]byte("k2"), "alice") || len(a) != 32 || strings.Contains(a, "alice") {
		t.Fatalf("hashID = %q", a)
	}
}

func TestInProcessSingletonAndHandles(t *testing.T) {
	ResetInProcessSingleton()
	if IsBrokerInProcess() || CurrentBroker() != nil {
		t.Fatal("singleton not reset")
	}
	if _, err := NewBrokerHandle(nil).ListGrants(); !errors.Is(err, ErrBrokerOutOfProcess) {
		t.Fatalf("handle without broker: %v", err)
	}
	b := scBroker(t, &scEmitter{})
	if !IsBrokerInProcess() || CurrentBroker() != b {
		t.Fatal("NewBroker did not register singleton")
	}
	if _, err := b.Exchange(context.Background(), "a", "s", "prov-a", "c", "n"); err != nil {
		t.Fatal(err)
	}
	grants, err := NewBrokerHandle(nil).ListGrants()
	if err != nil || len(grants) != 1 || grants[0].Provider != "prov-a" {
		t.Fatalf("grants via singleton: %+v %v", grants, err)
	}
}

func TestListGrantsAndRevoke_SkipExpiredEntries(t *testing.T) {
	b := scBroker(t, nil)
	key := cacheKey("prov-a", "c", "a", "s", "n")
	b.cache.set(key, &cacheEntry{tokenBytes: []byte("old"), deadline: time.Now().Add(-time.Second)})
	h := NewBrokerHandle(b)
	grants, err := h.ListGrants()
	if err != nil || len(grants) != 0 {
		t.Fatalf("expired grant listed: %+v %v", grants, err)
	}
	if err := h.Revoke(deriveScopedTokenID(b.hmacKey, key)); !errors.Is(err, ErrTokenNotFound) {
		t.Fatalf("revoke expired: %v", err)
	}
}

func TestRevokeAll_ByActorAndEveryone(t *testing.T) {
	em := &scEmitter{}
	b := scBroker(t, em)
	ctx := context.Background()
	for _, x := range []struct{ actor, prov string }{{"alice", "prov-a"}, {"alice", "prov-b"}, {"bob", "prov-a"}} {
		if _, err := b.Exchange(ctx, x.actor, "s-"+x.actor, x.prov, "c", "n"); err != nil {
			t.Fatal(err)
		}
	}
	h := NewBrokerHandle(b)

	n, err := h.RevokeAll("alice")
	if err != nil || n != 2 {
		t.Fatalf("RevokeAll(alice) = %d, %v", n, err)
	}
	grants, _ := h.ListGrants()
	if len(grants) != 1 || grants[0].ActorHMAC != hashID(b.hmacKey, "bob") {
		t.Fatalf("remaining grants = %+v", grants)
	}
	if n, err := h.RevokeAll("carol"); err != nil || n != 0 {
		t.Fatalf("RevokeAll(carol) = %d, %v", n, err)
	}
	if n, err := h.RevokeAll(""); err != nil || n != 1 {
		t.Fatalf("RevokeAll(all) = %d, %v", n, err)
	}
	if b.cache.size() != 0 {
		t.Fatal("cache not empty after revoking everyone")
	}

	revoked := em.byAction(ActionBrokerTokenRevoked)
	if len(revoked) != 3 {
		t.Fatalf("revocation events = %d, want 3", len(revoked))
	}
	for _, ev := range revoked {
		if ev.Extra["actor_hmac"] == "alice" || ev.Extra["actor_hmac"] == "bob" {
			t.Fatal("raw actor id in revocation event")
		}
		if ev.Extra["provider_revocation_attempted"] != false {
			t.Fatalf("event extra = %v", ev.Extra)
		}
	}
}

func TestRevoke_EmitterFailureDoesNotUndoRevocation(t *testing.T) {
	em := &scEmitter{err: errors.New("audit sink down")}
	b := scBroker(t, em)
	var evicted int
	key := cacheKey("prov-a", "c", "a", "s", "n")
	b.cache.set(key, &cacheEntry{tokenBytes: []byte("live"), deadline: time.Now().Add(time.Hour), onEvict: func() { evicted++ }})
	if err := NewBrokerHandle(b).Revoke(deriveScopedTokenID(b.hmacKey, key)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if evicted != 1 || b.cache.size() != 0 {
		t.Fatalf("evicted=%d size=%d", evicted, b.cache.size())
	}
	if len(em.byAction(ActionBrokerTokenRevoked)) != 1 {
		t.Fatal("revocation event not attempted")
	}
}

func TestCache_EvictExpiredZeroesAndCallsHook(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewTokenCacheWithLimit(ctx, 10)
	expired := []byte("expired-secret")
	live := []byte("live-secret")
	var hooks int
	c.set("k-expired", &cacheEntry{tokenBytes: expired, deadline: time.Now().Add(-time.Minute), onEvict: func() { hooks++ }})
	c.set("k-expired-nohook", &cacheEntry{tokenBytes: []byte("x"), deadline: time.Now().Add(-time.Minute)})
	c.set("k-live", &cacheEntry{tokenBytes: live, deadline: time.Now().Add(time.Hour)})

	c.evictExpired()
	if hooks != 1 {
		t.Fatalf("onEvict calls = %d", hooks)
	}
	if strings.Trim(string(expired), "\x00") != "" {
		t.Fatalf("expired token not zeroed: %q", expired)
	}
	if _, ok := c.get("k-live"); !ok || string(live) != "live-secret" {
		t.Fatal("live entry affected by eviction")
	}
	c.mu.RLock()
	n := len(c.entries)
	c.mu.RUnlock()
	if n != 1 {
		t.Fatalf("entries after eviction = %d", n)
	}
}

func TestCache_RemovalPathsCallOnEvict(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewTokenCacheWithLimit(ctx, 10)
	var hooks int
	hook := func() { hooks++ }
	future := time.Now().Add(time.Hour)

	c.set("a\x00c\x00x\x00sess-1\x00n", &cacheEntry{tokenBytes: []byte("1"), deadline: future, onEvict: hook})
	c.set("b\x00c\x00x\x00sess-2\x00n", &cacheEntry{tokenBytes: []byte("2"), deadline: future, onEvict: hook})
	c.set("single", &cacheEntry{tokenBytes: []byte("3"), deadline: future, onEvict: hook})

	c.deleteBySession("sess-1")
	c.delete("single")
	c.delete("absent")
	c.flush()
	if hooks != 3 {
		t.Fatalf("onEvict calls = %d, want 3", hooks)
	}
	c.mu.Lock()
	c.evictOldestLocked()
	c.mu.Unlock()
}

func TestKeyHelpers_MalformedKeys(t *testing.T) {
	if got := extractProviderFromKey("no-separators"); got != "no-separators" {
		t.Fatalf("provider = %q", got)
	}
	if got := extractActorFromKey("p\x00c"); got != "" {
		t.Fatalf("actor = %q", got)
	}
	if got := extractActorFromKey(cacheKey("p", "c", "actor", "s", "n")); got != "actor" {
		t.Fatalf("actor = %q", got)
	}
}

func TestDryRun_AuditAndScopeDerivation(t *testing.T) {
	em := &scEmitter{}
	b := scBroker(t, em)
	h := NewBrokerHandle(b)

	cases := map[string]string{
		"":                          "prov-a.*",
		"/usr/local/bin/GH.exe x":   "prov-a.gh",
		`C:\tools\deploy.sh --prod`: "prov-a.deploy",
		"curl https://example.test": "prov-a.curl",
	}
	for cmd, want := range cases {
		res, err := h.DryRunExchange("prov-a", cmd)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.ScopesRequested) != 1 || res.ScopesRequested[0] != want {
			t.Errorf("DryRunExchange(%q) scopes = %v, want %s", cmd, res.ScopesRequested, want)
		}
		if res.PolicyDecision != "allow" || res.ScopedTokenTTL != time.Hour {
			t.Errorf("result = %+v", res)
		}
	}
	evs := em.byAction(ActionBrokerDryRunRequested)
	if len(evs) != len(cases) {
		t.Fatalf("dry-run events = %d", len(evs))
	}
	if b.cache.size() != 0 {
		t.Fatal("dry run populated the cache")
	}
}

func TestExchange_WithoutAuditEmitterWithholdsCredential(t *testing.T) {
	b := scBroker(t, nil)
	if _, err := b.Exchange(context.Background(), "a", "s", "prov-a", "c", "n"); err == nil || !strings.Contains(err.Error(), "credential withheld") {
		t.Fatalf("want credential withheld, got %v", err)
	}
}
