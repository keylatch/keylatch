package bw

import (
	"context"
	"testing"
	"time"
)

type bkBWCountRunner struct {
	gets int
}

func (r *bkBWCountRunner) Run(_ context.Context, _ string, args []string, _ []byte) ([]byte, []byte, int, error) {
	if len(args) > 0 && args[0] == "get" {
		r.gets++
	}
	return []byte(`{"id":"id1","name":"myconn","fields":[{"name":"api_key","value":"fresh","type":1}]}`), nil, 0, nil
}

func TestFetchItem_ExpiredEntryZeroedAndRefetched(t *testing.T) {
	runner := &bkBWCountRunner{}
	b := &BitwardenBackend{opts: Options{Runner: runner}, bin: "/fake/bw"}

	stale := []byte("stale-secret")
	login := &bwLogin{Username: "u", Password: "p"}
	b.cache.Store("myconn", cacheEntry{
		item: bwItem{
			ID:     "id1",
			Login:  login,
			Fields: []bwField{{Name: "api_key", Value: stale, Type: 1}},
		},
		expiresAt: time.Now().Add(-time.Minute),
	})

	val, _, err := b.Get(context.Background(), "default/myconn/api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(val) != "fresh" {
		t.Fatalf("Get = %q, want refetched value", val)
	}
	if runner.gets != 1 {
		t.Fatalf("expected one refetch, got %d", runner.gets)
	}
	for i, c := range stale {
		if c != 0 {
			t.Fatalf("expired field byte %d not zeroed", i)
		}
	}
	if login.Password != "" || login.Username != "" {
		t.Fatalf("expired login not cleared: %+v", login)
	}

	v, ok := b.cache.Load("myconn")
	if !ok {
		t.Fatal("refetched item not cached")
	}
	if !time.Now().Before(v.(cacheEntry).expiresAt) {
		t.Fatal("new cache entry already expired")
	}
}

func TestEvictCacheEntry_ClearsLogin(t *testing.T) {
	b := &BitwardenBackend{}
	login := &bwLogin{Username: "u", Password: "p"}
	b.cache.Store("c", cacheEntry{item: bwItem{Login: login}, expiresAt: time.Now().Add(time.Hour)})
	b.evictCacheEntry("c")
	if login.Password != "" || login.Username != "" {
		t.Fatalf("login not cleared: %+v", login)
	}
	if _, ok := b.cache.Load("c"); ok {
		t.Fatal("entry still cached")
	}
}

func TestIsErrNotFound_Nil(t *testing.T) {
	if isErrNotFound(nil) {
		t.Fatal("nil error must not be treated as not found")
	}
}

func TestBwFieldUnmarshal_RejectsNonObject(t *testing.T) {
	var f bwField
	if err := f.UnmarshalJSON([]byte(`"str"`)); err == nil {
		t.Fatal("expected error for non-object field")
	}
}

func (r *bkBWCountRunner) RunEnv(ctx context.Context, name string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return r.Run(ctx, name, args, stdin)
}
