//go:build securitysuite

// Requires the securitysuite build tag; excluded from the ordinary
// go test ./... run. Run with: go test -tags securitysuite ./...
package sharedsecret_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/sharedsecret"
	"github.com/keylatch/keylatch/internal/trust"
)

// KNOWN-FAILING: Read accepts any nonzero PresenceProof.ConfirmedAt
// timestamp as proof of hardware presence, with no signature, freshness, or
// replay check, so a year-old unsigned timestamp is accepted.
func TestSecurityRegression_SharedSecretPresence(t *testing.T) {
	priv, pub, e := sharedsecret.GenerateAGEKeyPair()
	if e != nil {
		t.Fatal(e)
	}
	member := team.Member{ID: "audit", HMAC: "audit-hmac", Role: team.RoleDeveloper, Status: team.MemberActive, AgePublicKey: pub}
	s, e := sharedsecret.Create(context.Background(), "audit-team", "audit-secret", []byte("synthetic-secret"), []team.Member{member})
	if e != nil {
		t.Fatal(e)
	}
	member.AgePublicKey = priv
	value, e := sharedsecret.Read(context.Background(), s, member, trust.PresenceProof{ConfirmedAt: time.Now().Add(-365 * 24 * time.Hour)})
	if e == nil && string(value) == "synthetic-secret" {
		t.Fatal("unsigned year-old timestamp accepted as hardware presence proof")
	}
}
