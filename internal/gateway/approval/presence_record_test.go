package approval

import (
	"context"
	"errors"
	"regexp"
	"testing"
)

// A decision's presence proof is part of what the approver key signs, so a
// record whose proof was edited, added or removed is not accepted.
func TestApprovalRecordMAC(t *testing.T) {
	ctx := context.Background()
	p := Presence{Digest: "d1", Method: "tty+localauth"}

	for name, tamper := range map[string]func(*ApprovalRequest){
		"digest swapped": func(ar *ApprovalRequest) { ar.PresenceDigest = "d2" },
		"method swapped": func(ar *ApprovalRequest) { ar.PresenceMethod = "tty" },
		"proof removed":  func(ar *ApprovalRequest) { ar.PresenceDigest, ar.PresenceMethod = "", "" },
		"signature cut":  func(ar *ApprovalRequest) { ar.Signature = ar.Signature[:len(ar.Signature)-4] },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ar := makeRequest(t, dir)
			if err := ApproveWithPresence(ctx, dir, ar.Token, Digest(ar), "", p, testKey); err != nil {
				t.Fatal(err)
			}
			got, err := Get(ctx, dir, ar.Token)
			if err != nil {
				t.Fatal(err)
			}
			if got.PresenceDigest != p.Digest || got.PresenceMethod != p.Method {
				t.Fatalf("record carries %q/%q, want %q/%q", got.PresenceDigest, got.PresenceMethod, p.Digest, p.Method)
			}
			tamper(got)
			mustWrite(t, dir, got)
			if err := Verify(ctx, dir, ar.Token, "req-hash-abc", testPub); !errors.Is(err, ErrUnsigned) {
				t.Fatalf("Verify of a tampered record = %v, want ErrUnsigned", err)
			}
		})
	}

	t.Run("untouched record verifies", func(t *testing.T) {
		dir := t.TempDir()
		ar := makeRequest(t, dir)
		if err := DenyWithPresence(ctx, dir, ar.Token, Digest(ar), "no", p, testKey); err != nil {
			t.Fatal(err)
		}
		got, err := Get(ctx, dir, ar.Token)
		if err != nil || got.Status != StatusDenied || got.PresenceDigest != p.Digest {
			t.Fatalf("denied record = %+v, %v", got, err)
		}
	})
}

// specTokenFormat is the shape every approval token has to fit; tokens name
// files, so nothing outside it is ever opened.
var specTokenFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)

func TestApprovalTokenFormat(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		token, err := newApprovalToken()
		if err != nil {
			t.Fatal(err)
		}
		if !specTokenFormat.MatchString(token) || !ValidToken(token) {
			t.Fatalf("generated token %q is outside the token format", token)
		}
		if seen[token] {
			t.Fatalf("token %q was generated twice", token)
		}
		seen[token] = true
	}
	for _, bad := range []string{"", "x", "../../etc/passwd", "apv_/../../x", "apv_" + string(make([]byte, 32)), "apv_0123456789abcdef0123456789abcdeg", "apv_0123456789ABCDEF0123456789ABCDEF"} {
		if ValidToken(bad) {
			t.Errorf("ValidToken(%q) accepted a malformed token", bad)
		}
	}
}
