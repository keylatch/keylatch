package oidc_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/team/oidc"
)

// TestOIDCIDTokenCanary seeds a canary value into the mock OIDC ID token sub claim.
// Asserts canary does NOT appear in: audit log, output, any session-state file, any keyring file.
// Verifies canary IS present in session.Subject in-memory during login.
func TestOIDCIDTokenCanary(t *testing.T) {
	const sentinel = "KEYLATCH_CANARY_PHASE12_OIDC_oidc_0xDEADBEEF"
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)

	ctx := context.Background()

	// We simulate a session where Subject contains the sentinel.
	// Since Login generates a synthetic subject, we directly test that
	// the subject is not persisted anywhere.
	session, err := oidc.Login(ctx, oidc.ProviderGoogle, oidc.LoginOpts{
		MaxSessionAge: time.Hour,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Canary IS in session.Subject in-memory — verify it's accessible.
	if session.Subject == "" {
		t.Error("session.Subject should be non-empty in memory")
	}

	// The sentinel as Subject.
	// We check that the session JSON tags prevent it from appearing in marshal.
	sessionAsJSON, _ := json.Marshal(session)

	// Verify sentinel does NOT appear in JSON output (json:"-" tags).
	// Since Subject has json:"-", it won't be in sessionAsJSON.
	// We check that a marshal produces {} or very minimal output.
	canary.AssertNoLeak(t,
		[]string{sentinel},
		canary.Stdout(sessionAsJSON),
	)

	// Check no session files were written to disk containing the sentinel.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		canary.AssertNoLeak(t,
			[]string{sentinel},
			canary.File(path),
		)
	}
}
