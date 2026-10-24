//go:build !windows

package control

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/presence"
)

func TestKeyAllowSummaryShowsBeforeAndAdditions(t *testing.T) {
	kp := KeyPolicyRequest{Connection: "c", Field: "F", Operations: []string{"decrypt", "sign"}, HostKeys: []string{"SHA256:x"}, SSHAgent: true}

	fresh := keyAllowSummary(kp, nil)
	for _, want := range []string{"allow key operations on c field F", "before:   new entry", "adds:     operations decrypt,sign", "host keys SHA256:x", "secret:   unchanged"} {
		if !strings.Contains(fresh, want) {
			t.Errorf("summary lacks %q:\n%s", want, fresh)
		}
	}

	widened := keyAllowSummary(kp, &allowedEntry{Operations: []string{"encrypt"}, Algorithms: []string{"A256GCM"}, AgentDecrypt: true})
	if !strings.Contains(widened, "before:   operations encrypt; algorithms A256GCM; agent decrypt true; ssh-agent host keys 0") {
		t.Errorf("summary does not show the entry as it stands:\n%s", widened)
	}
}

type keyPresenceFunc func(context.Context, presence.Action, string) error

func (keyPresenceFunc) Name() string { return "test" }
func (f keyPresenceFunc) Confirm(ctx context.Context, action presence.Action, summary string) error {
	return f(ctx, action, summary)
}

func TestKeyPolicyAllowAuthenticatesEffectiveEdit(t *testing.T) {
	dir := t.TempDir()
	store := keyops.NewStore(filepath.Join(dir, "key-operations.json"), keyops.MACKey(bytes.Repeat([]byte{3}, 32)))
	rec := &recordedAudit{}
	admin, err := keyops.NewAdmin(store, rec)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{KeyAdmin: admin})
	ask := KeyPolicyRequest{Action: "allow", Connection: "c", Field: "F", Secret: "s", Operations: []string{"sign"}}

	resp := srv.keyPolicy(t.Context(), KindHuman, &ask)
	if resp.OK || resp.ExitCode != exitcode.SecurityBlock {
		t.Fatalf("an allow without a proof was accepted: %+v", resp)
	}
	if doc, _ := store.Load(); len(doc) != 0 {
		t.Fatalf("the unproven allow was applied: %+v", doc)
	}

	ask.PresenceDigest = "digest-of-what-the-human-read"
	if resp = srv.keyPolicy(t.Context(), KindHuman, &ask); resp.OK {
		t.Fatal("a caller-supplied digest bypassed authentication")
	}
	var summary string
	calls := 0
	srv.cfg.KeyPresence = keyPresenceFunc(func(_ context.Context, action presence.Action, text string) error {
		calls++
		if action != presence.ActionKeyAllow {
			t.Fatalf("wrong presence action: %s", action)
		}
		summary = text
		return nil
	})
	if resp = srv.keyPolicy(t.Context(), KindHuman, &ask); !resp.OK {
		t.Fatalf("an authenticated allow was refused: %+v", resp)
	}
	if !strings.Contains(summary, "before:") || !strings.Contains(summary, "after:") || !strings.Contains(summary, "sign") {
		t.Fatalf("presence did not show the effective edit: %s", summary)
	}
	if !strings.Contains(rec.dump(), presence.Digest(presence.ActionKeyAllow, summary)) || strings.Contains(rec.dump(), ask.PresenceDigest) {
		t.Fatalf("the audit event must use only the server-derived proof: %s", rec.dump())
	}

	ask.Field = "G"
	if resp = srv.keyPolicy(t.Context(), KindAgent, &ask); resp.OK {
		t.Fatalf("an agent widened the allowlist with a borrowed proof: %+v", resp)
	}
	if calls != 1 {
		t.Fatal("an agent triggered a presence prompt")
	}
	for _, failure := range []error{presence.ErrDenied, presence.ErrUnavailable, context.Canceled} {
		srv.cfg.KeyPresence = keyPresenceFunc(func(context.Context, presence.Action, string) error { return failure })
		if resp = srv.keyPolicy(t.Context(), KindHuman, &ask); resp.OK {
			t.Fatalf("authentication failure accepted: %v", failure)
		}
	}
	doc, err := store.Load()
	if err != nil || len(doc["c"]) != 1 {
		t.Fatalf("failed authentication changed policy: %v, %v", doc, err)
	}
}
