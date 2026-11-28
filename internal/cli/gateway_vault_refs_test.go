package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/store"
)

type refFakeRunner struct {
	out    []byte
	stderr []byte
	code   int
	calls  int
}

func (f *refFakeRunner) Run(context.Context, string, []string, []byte) ([]byte, []byte, int, error) {
	f.calls++
	return append([]byte(nil), f.out...), f.stderr, f.code, nil
}

func (f *refFakeRunner) RunEnv(ctx context.Context, bin string, args []string, stdin []byte, _ []string) ([]byte, []byte, int, error) {
	return f.Run(ctx, bin, args, stdin)
}

func stubStoreResolver(t *testing.T, r store.CommandRunner) {
	t.Helper()
	orig := storeNewResolver
	storeNewResolver = func() *store.Resolver {
		return store.NewResolver(r).WithBinOverride("op", "/fake/op")
	}
	t.Cleanup(func() { storeNewResolver = orig })
}

func readerReturning(stored string) *gatewayVaultReader {
	return &gatewayVaultReader{read: func(context.Context, string) ([]byte, error) {
		return []byte(stored), nil
	}}
}

func TestGatewayVaultReader_ResolvesProviderRef(t *testing.T) {
	runner := &refFakeRunner{out: []byte("sk-resolved-secret")}
	stubStoreResolver(t, runner)

	got, meta, err := readerReturning("op://Private/openai/api_key").Get(context.Background(), "default/ai/openai/api_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "sk-resolved-secret" {
		t.Fatalf("got %q, want resolved value", got)
	}
	if meta.Path != "default/ai/openai/api_key" {
		t.Fatalf("meta.Path = %q", meta.Path)
	}
}

func TestGatewayVaultReader_PlainValueUntouched(t *testing.T) {
	runner := &refFakeRunner{out: []byte("must-not-be-used")}
	stubStoreResolver(t, runner)

	got, _, err := readerReturning("sk-plain").Get(context.Background(), "p")
	if err != nil || string(got) != "sk-plain" {
		t.Fatalf("got %q, %v", got, err)
	}
	if runner.calls != 0 {
		t.Fatalf("resolver invoked %d times for a plain value", runner.calls)
	}
}

func TestGatewayVaultReader_ResolveFailureFailsClosedWithoutLeak(t *testing.T) {
	const ref = "op://Private/openai/api_key"
	runner := &refFakeRunner{stderr: []byte("secret-stderr-detail"), code: 1}
	stubStoreResolver(t, runner)

	got, _, err := readerReturning(ref).Get(context.Background(), "p")
	if err == nil {
		t.Fatal("expected error")
	}
	if got != nil {
		t.Fatalf("value returned on failure: %q", got)
	}
	if !errors.Is(err, errGatewayRefResolve) {
		t.Fatalf("err = %v, want errGatewayRefResolve", err)
	}
	for _, leak := range []string{ref, "Private", "secret-stderr-detail", "op://"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("error leaks %q: %v", leak, err)
		}
	}
}

func TestGatewayVaultReader_ClearsStoredRefBytes(t *testing.T) {
	stubStoreResolver(t, &refFakeRunner{out: []byte("resolved")})
	stored := []byte("op://Private/openai/api_key")
	r := &gatewayVaultReader{read: func(context.Context, string) ([]byte, error) { return stored, nil }}

	if _, _, err := r.Get(context.Background(), "p"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, b := range stored {
		if b != 0 {
			t.Fatalf("stored ref bytes not cleared: %q", stored)
		}
	}
}
