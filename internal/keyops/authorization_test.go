package keyops

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/audit"
)

type policyAuditFunc func(context.Context, audit.Event) error

func (f policyAuditFunc) Emit(ctx context.Context, event audit.Event) error { return f(ctx, event) }

func TestFailedAuditCannotPublishOrRestorePermissions(t *testing.T) {
	store, admin, _ := seeded(t)
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	admin.audit = policyAuditFunc(func(_ context.Context, event audit.Event) error {
		if event.Extra["change"] == "allow" {
			close(entered)
			<-release
			return errors.New("audit unavailable")
		}
		return nil
	})
	allowed := make(chan error, 1)
	go func() {
		allowed <- admin.Allow(t.Context(), human, Change{Connection: "app-local", Field: "SECOND", Secret: "s", Operations: []string{"sign"}})
	}()
	<-entered
	revoked := make(chan error, 1)
	go func() { revoked <- admin.Revoke(t.Context(), human, Change{Connection: "app-local"}) }()
	onDisk, readErr := os.ReadFile(store.path)
	close(release)
	if err := <-allowed; !errors.Is(err, ErrUnavailable) {
		t.Fatalf("audit failure accepted: %v", err)
	}
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	if readErr != nil || string(onDisk) != string(before) {
		t.Fatal("an unaudited widening was published")
	}
	doc, err := store.Load()
	if err != nil || len(doc) != 0 {
		t.Fatalf("failed audit restored revoked permissions: %v, %v", doc, err)
	}
}

func TestAllowVerifiedBindsExactPolicyAndChecksCancellation(t *testing.T) {
	store, admin, _ := seeded(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	err := admin.AllowVerified(ctx, human, Change{
		Connection: "app-local", Field: "RELEASE_SIGNING_KEY", Secret: "evil\x1b[2J\u202e",
		Operations: []string{"verify"}, HostKeys: []string{"SHA256:exact-host"},
	}, func(_ context.Context, summary string) (string, error) {
		for _, want := range []string{"before:", "after:", "default/app/release", "jwt_sign", "verify", "SHA256:exact-host"} {
			if !strings.Contains(summary, want) {
				t.Errorf("summary omits %q: %s", want, summary)
			}
		}
		if strings.ContainsAny(summary, "\x1b\u202e") {
			t.Error("summary contains display controls")
		}
		cancel()
		return "trusted", nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled approval accepted: %v", err)
	}
	ref, err := store.Lookup("app-local", "RELEASE_SIGNING_KEY")
	if err != nil || ref.Policy.Secret != "default/app/release" {
		t.Fatalf("canceled approval changed policy: %v, %v", ref, err)
	}
}
