package trust

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/team"
)

func trX25519PubHex(t *testing.T) string {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(k.PublicKey().Bytes())
}

func trWriteTeam(t *testing.T, tm team.Team) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	b, err := json.Marshal(tm)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "team.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSharedSecretCreateValidation(t *testing.T) {
	trHome(t)
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--plaintext-hex", "00"}, "--name-hmac is required"},
		{[]string{"--name-hmac", "h"}, "--plaintext-hex is required"},
		{[]string{"--name-hmac", "h", "--plaintext-hex", "zz"}, "--plaintext-hex: encoding/hex"},
		{[]string{"--name-hmac", "h", "--plaintext-hex", "00"}, "shared-secret create: team not configured"},
	}
	for _, tc := range cases {
		_, _, err := trRunShared(t, append([]string{"create"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestSharedSecretCreateEncryptsForActiveMembers(t *testing.T) {
	trHome(t)
	trWriteTeam(t, team.Team{
		ID: "team-1",
		Members: []team.Member{
			{ID: "m1", HMAC: "h1", Status: team.MemberActive, AgePublicKey: trX25519PubHex(t)},
			{ID: "m2", HMAC: "h2", Status: team.MemberActive, AgePublicKey: trX25519PubHex(t)},
			{ID: "m3", HMAC: "h3", Status: team.MemberActive},
			{ID: "m4", HMAC: "h4", Status: team.MemberRemoved, AgePublicKey: trX25519PubHex(t)},
		},
	})

	out, _, err := trRunShared(t, "create", "--name-hmac", "nh", "--plaintext-hex", "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Shared secret created: id=") || !strings.HasSuffix(out, " recipients=2\n") {
		t.Fatalf("out = %q", out)
	}
	if strings.Contains(out, "deadbeef") {
		t.Fatal("plaintext leaked to output")
	}

	out, _, err = trRunShared(t, "create", "--name-hmac", "nh", "--plaintext-hex", "deadbeef", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var res struct {
		ID         string `json:"id"`
		NameHMAC   string `json:"name_hmac"`
		Recipients int    `json:"recipients"`
		Version    int    `json:"version"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("bad json %q: %v", out, err)
	}
	if res.ID == "" || res.NameHMAC == "" || res.NameHMAC == "nh" || res.Recipients != 2 || res.Version != 1 {
		t.Fatalf("res = %+v", res)
	}
}

func TestSharedSecretCreateRejectsBadMemberKey(t *testing.T) {
	trHome(t)
	trWriteTeam(t, team.Team{ID: "team-1", Members: []team.Member{
		{ID: "m1", Status: team.MemberActive, AgePublicKey: "not-hex"},
	}})
	_, _, err := trRunShared(t, "create", "--name-hmac", "nh", "--plaintext-hex", "00")
	if err == nil || !strings.Contains(err.Error(), `encrypt for member "m1"`) {
		t.Fatalf("err = %v", err)
	}
}

func TestSharedSecretRewrapRequiresHardware(t *testing.T) {
	trHome(t)
	out, _, err := trRunShared(t, "rewrap", "--id", "s1", "--member-id", "m1")
	if err == nil || !strings.Contains(err.Error(), "not yet wired to hardware challenge") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(out, "Rewrap requires hardware presence proof.") {
		t.Fatalf("out = %q", out)
	}
}

func TestSharedSecretRotate(t *testing.T) {
	trHome(t)
	t.Setenv("KEYLATCH_TEAM_DIR", t.TempDir())
	_, _, err := trRunShared(t, "rotate")
	if !errors.Is(err, team.ErrTeamNotConfigured) {
		t.Fatalf("no team: err = %v", err)
	}

	trWriteTeam(t, team.Team{ID: "t", Members: []team.Member{
		{ID: "a", Status: team.MemberActive},
		{ID: "b", Status: team.MemberActive},
		{ID: "c", Status: team.MemberRemoved},
	}})
	out, _, err := trRunShared(t, "rotate", "--id", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Rotate will re-encrypt for 2 active members.\n") {
		t.Fatalf("out = %q", out)
	}
}

func TestSharedSecretRevealRequiresProofRoot(t *testing.T) {
	trHome(t)
	_, _, err := trRunShared(t, "reveal", "--id", "s1")
	if err == nil || !strings.Contains(err.Error(), "--proof-root is required") {
		t.Fatalf("err = %v", err)
	}
	out, _, err := trRunShared(t, "reveal", "--id", "s1", "--proof-root", "r1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Hardware presence proof accepted.\n") {
		t.Fatalf("out = %q", out)
	}
}
