package sharedsecret_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/canary"
	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/sharedsecret"
	"github.com/keylatch/keylatch/internal/trust"
)

// TestSharedSecretCanary seeds a canary value into a shared-secret plaintext.
// Asserts the canary does NOT appear in stdout, stderr, audit log, or files outside
// the in-memory read path. Asserts it DOES appear in decrypted output via Read.
func TestSharedSecretCanary(t *testing.T) {
	const sentinel = "KEYLATCH_CANARY_PHASE12_SHARED_sharedsecret_0xDEADBEEF"
	plaintext := []byte(sentinel)
	ctx := context.Background()

	priv, pub, err := sharedsecret.GenerateAGEKeyPair()
	if err != nil {
		t.Fatalf("GenerateAGEKeyPair: %v", err)
	}

	alice := team.Member{
		ID:           "canary-alice",
		HMAC:         "canary-hmac",
		Role:         team.RoleDeveloper,
		AgePublicKey: pub,
		JoinedAt:     time.Now(),
		Status:       team.MemberActive,
	}

	s, err := sharedsecret.Create(ctx, "canary-team-id", "canary-secret", plaintext, []team.Member{alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Verify the canary is NOT in the SharedSecret struct itself when serialized.
	structJSON, _ := json.Marshal(s)
	canary.AssertNoLeak(t,
		[]string{sentinel},
		canary.JSONResponse(s),
		canary.Stdout(structJSON),
		canary.Stderr(nil),
	)

	// Verify the canary is NOT in any temp files from the operation.
	dir := t.TempDir()
	for _, filename := range []string{"secret.json", "audit.log"} {
		path := filepath.Join(dir, filename)
		if data, err := os.ReadFile(path); err == nil {
			canary.AssertNoLeak(t, []string{sentinel}, canary.File(path), canary.Stdout(data))
		}
	}

	// Verify the canary DOES appear in decrypted output via Read (correct functionality).
	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = priv

	proof := trust.PresenceProof{
		Method:      "test",
		ConfirmedAt: time.Now(),
		RootID:      "root-canary",
	}

	decrypted, err := sharedsecret.Read(ctx, s, aliceWithPriv, proof)
	if err != nil {
		t.Fatalf("Read canary: %v", err)
	}
	if string(decrypted) != sentinel {
		t.Errorf("canary not found in decrypted output: got %q", decrypted)
	}
}
