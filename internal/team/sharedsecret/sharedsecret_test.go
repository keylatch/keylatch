package sharedsecret_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/sharedsecret"
	"github.com/keylatch/keylatch/internal/trust"
)

func newTestMember(t *testing.T, id string) (team.Member, string) {
	t.Helper()
	privHex, pubHex, err := sharedsecret.GenerateAGEKeyPair()
	if err != nil {
		t.Fatalf("GenerateAGEKeyPair: %v", err)
	}
	m := team.Member{
		ID:           id,
		HMAC:         "hmac-" + id,
		Role:         team.RoleDeveloper,
		AgePublicKey: pubHex,
		JoinedAt:     time.Now(),
		Status:       team.MemberActive,
	}
	return m, privHex
}

func validProof() trust.PresenceProof {
	return trust.PresenceProof{
		Method:      "test",
		ConfirmedAt: time.Now(),
		RootID:      "root-test",
	}
}

func TestCreate_Read_RoundTrip(t *testing.T) {
	ctx := context.Background()
	alice, alicePriv := newTestMember(t, "alice")

	// Set AgePublicKey to privKey for test — Read uses it as decryption key.
	// In production the member would have separate pub/priv.
	// For this test, we use the private key as the AgePublicKey in the member for decryption.
	plaintext := []byte("super-secret-value")

	// Create with public key.
	s, err := sharedsecret.Create(ctx, "test-team-id", "my-secret", plaintext, []team.Member{alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(s.Recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(s.Recipients))
	}
	if s.Version != 1 {
		t.Errorf("Version = %d, want 1", s.Version)
	}

	// For decryption, use alice's private key via the AgePublicKey field.
	// We simulate by setting AgePublicKey to the private key hex.
	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = alicePriv

	// Update recipient HMAC to match.
	s.Recipients[0].MemberIDHMAC = alice.HMAC

	got, err := sharedsecret.Read(ctx, s, aliceWithPriv, validProof())
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", got, plaintext)
	}
}

func TestRead_LLMSessionBlocked(t *testing.T) {
	ctx := sharedsecret.WithLLMSession(context.Background())
	alice, alicePriv := newTestMember(t, "alice")

	s, err := sharedsecret.Create(context.Background(), "test-team-id", "secret", []byte("value"), []team.Member{alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = alicePriv

	_, err = sharedsecret.Read(ctx, s, aliceWithPriv, validProof())
	if err != sharedsecret.ErrLLMSessionBlocked {
		t.Errorf("Read in LLM session: got %v, want ErrLLMSessionBlocked", err)
	}
}

func TestRead_HardwarePresenceRequired(t *testing.T) {
	ctx := context.Background()
	alice, alicePriv := newTestMember(t, "alice")

	s, err := sharedsecret.Create(ctx, "test-team-id", "secret", []byte("value"), []team.Member{alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = alicePriv

	emptyProof := trust.PresenceProof{}
	_, err = sharedsecret.Read(ctx, s, aliceWithPriv, emptyProof)
	if err != sharedsecret.ErrHardwarePresenceRequired {
		t.Errorf("Read without proof: got %v, want ErrHardwarePresenceRequired", err)
	}
}

func TestRotateWithPlaintext_ExcludesRemovedMember(t *testing.T) {
	ctx := context.Background()
	alice, alicePriv := newTestMember(t, "alice")
	bob, _ := newTestMember(t, "bob")

	plaintext := []byte("team-secret")
	s, err := sharedsecret.Create(ctx, "test-team-id", "secret", plaintext, []team.Member{alice, bob})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Bob is removed.
	bob.Status = team.MemberRemoved
	rotated, err := sharedsecret.RotateWithPlaintext(ctx, s, plaintext, []team.Member{alice, bob})
	if err != nil {
		t.Fatalf("RotateWithPlaintext: %v", err)
	}

	// Only alice should be in the rotated secret.
	if len(rotated.Recipients) != 1 {
		t.Errorf("expected 1 recipient after rotation, got %d", len(rotated.Recipients))
	}
	if rotated.Recipients[0].MemberIDHMAC != alice.HMAC {
		t.Errorf("expected alice's HMAC after rotation, got %q", rotated.Recipients[0].MemberIDHMAC)
	}
	if rotated.Version != s.Version+1 {
		t.Errorf("Version = %d, want %d", rotated.Version, s.Version+1)
	}

	// Alice can still read.
	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = alicePriv
	got, err := sharedsecret.Read(ctx, rotated, aliceWithPriv, validProof())
	if err != nil {
		t.Fatalf("Read after rotation: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("decrypted after rotation = %q, want %q", got, plaintext)
	}
}

func TestAGEStrictFail_CorruptedCiphertext(t *testing.T) {
	ctx := context.Background()
	alice, alicePriv := newTestMember(t, "alice")

	s, err := sharedsecret.Create(ctx, "test-team-id", "secret", []byte("value"), []team.Member{alice})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Corrupt the ciphertext.
	if len(s.Recipients) > 0 && len(s.Recipients[0].EncryptedPayload) > 40 {
		s.Recipients[0].EncryptedPayload[40] ^= 0xFF
	}

	aliceWithPriv := alice
	aliceWithPriv.AgePublicKey = alicePriv

	_, err = sharedsecret.Read(ctx, s, aliceWithPriv, validProof())
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "decrypt") && err != sharedsecret.ErrDecryptionFailed {
		t.Errorf("unexpected error for corruption: %v", err)
	}
}
