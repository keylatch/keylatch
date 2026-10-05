package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDecisionsRejectMalformedTokens(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "approvals")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "outside.json")
	original := []byte(`{"token":"../outside","status":"pending","expires_at":"2099-01-01T00:00:00Z"}`)
	if err := os.WriteFile(victim, original, 0o600); err != nil {
		t.Fatal(err)
	}
	valid := tok("valid")
	for _, bad := range []string{
		"", "../outside", "apv_../../outside", "apv_" + "ABCDEF0123456789ABCDEF0123456789",
		"apv_0123", valid + "0", valid[:len(valid)-1], " " + valid, valid + "\n", "apv_x/../" + valid[4:],
	} {
		if err := Approve(context.Background(), dir, bad, testKey); !errors.Is(err, ErrNotFound) {
			t.Errorf("Approve(%q) = %v, want ErrNotFound", bad, err)
		}
		if err := Deny(context.Background(), dir, bad, testKey); !errors.Is(err, ErrNotFound) {
			t.Errorf("Deny(%q) = %v, want ErrNotFound", bad, err)
		}
		if _, err := Get(context.Background(), dir, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = %v, want ErrNotFound", bad, err)
		}
		if err := Verify(context.Background(), dir, bad, "h", testPub); !errors.Is(err, ErrNotFound) {
			t.Errorf("Verify(%q) = %v, want ErrNotFound", bad, err)
		}
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != string(original) {
		t.Fatalf("file outside the approvals directory changed: %q, %v", got, err)
	}
}

func TestDecisionsRefuseSymlinkedRecords(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs extra privileges on Windows")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "approvals")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	token := tok("linked")
	victim := filepath.Join(root, "policy.json")
	original := []byte(`{"token":"` + token + `","status":"pending","expires_at":"2099-01-01T00:00:00Z"}`)
	if err := os.WriteFile(victim, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(dir, token+".json")); err != nil {
		t.Fatal(err)
	}
	if err := Approve(context.Background(), dir, token, testKey); err == nil {
		t.Fatal("Approve followed a symlink out of the approvals directory")
	}
	if pending, _ := Pending(context.Background(), dir); len(pending) != 0 {
		t.Fatalf("Pending listed a symlinked record: %+v", pending)
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != string(original) {
		t.Fatalf("symlink target changed: %q, %v", got, err)
	}
}

func TestRecordNamedForAnotherTokenIsIgnored(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	other := tok("other")
	data, err := os.ReadFile(filepath.Join(dir, ar.Token+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, other+".json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Get(context.Background(), dir, other); err == nil {
		t.Fatal("Get accepted a record whose token does not match its file name")
	}
	pending, err := Pending(context.Background(), dir)
	if err != nil || len(pending) != 1 || pending[0].Token != ar.Token {
		t.Fatalf("Pending = %+v, %v; want only %s", pending, err, ar.Token)
	}
}

func TestDecisionNeedsApproverKey(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	for _, key := range []ed25519.PrivateKey{nil, make(ed25519.PrivateKey, 10)} {
		if err := Approve(context.Background(), dir, ar.Token, key); !errors.Is(err, ErrUnsigned) {
			t.Fatalf("Approve without a key = %v, want ErrUnsigned", err)
		}
	}
	got, err := Get(context.Background(), dir, ar.Token)
	if err != nil || got.Status != StatusPending {
		t.Fatalf("record changed without a key: %+v, %v", got, err)
	}
}

func TestVerifyRejectsForgedDecisions(t *testing.T) {
	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func(t *testing.T, dir string, ar *ApprovalRequest){
		"approved without signature": func(t *testing.T, dir string, ar *ApprovalRequest) {
			ar.Status = StatusApproved
			mustWrite(t, dir, ar)
		},
		"signed by another key": func(t *testing.T, dir string, ar *ApprovalRequest) {
			if err := Approve(context.Background(), dir, ar.Token, otherKey); err != nil {
				t.Fatal(err)
			}
		},
		"connection changed after signing": func(t *testing.T, dir string, ar *ApprovalRequest) {
			if err := Approve(context.Background(), dir, ar.Token, testKey); err != nil {
				t.Fatal(err)
			}
			got, _ := Get(context.Background(), dir, ar.Token)
			got.Connection = "prod-database"
			mustWrite(t, dir, got)
		},
		"denial flipped to approved": func(t *testing.T, dir string, ar *ApprovalRequest) {
			if err := Deny(context.Background(), dir, ar.Token, testKey); err != nil {
				t.Fatal(err)
			}
			got, _ := Get(context.Background(), dir, ar.Token)
			got.Status = StatusApproved
			mustWrite(t, dir, got)
		},
		"expiry extended after signing": func(t *testing.T, dir string, ar *ApprovalRequest) {
			if err := Approve(context.Background(), dir, ar.Token, testKey); err != nil {
				t.Fatal(err)
			}
			got, _ := Get(context.Background(), dir, ar.Token)
			got.ExpiresAt = got.ExpiresAt.Add(24 * time.Hour)
			mustWrite(t, dir, got)
		},
		"signature copied from another approval": func(t *testing.T, dir string, ar *ApprovalRequest) {
			donor := makeRequest(t, dir)
			if err := Approve(context.Background(), dir, donor.Token, testKey); err != nil {
				t.Fatal(err)
			}
			signed, _ := Get(context.Background(), dir, donor.Token)
			ar.Status = StatusApproved
			ar.DecidedAt = signed.DecidedAt
			ar.Signature = signed.Signature
			mustWrite(t, dir, ar)
		},
		"garbage signature": func(t *testing.T, dir string, ar *ApprovalRequest) {
			ar.Status = StatusApproved
			ar.Signature = base64.StdEncoding.EncodeToString([]byte("not a signature"))
			mustWrite(t, dir, ar)
		},
	}
	for name, forge := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			ar := makeRequest(t, dir)
			forge(t, dir, ar)
			if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, testPub); !errors.Is(err, ErrUnsigned) {
				t.Fatalf("Verify = %v, want ErrUnsigned", err)
			}
		})
	}
}

func TestVerifyAcceptsSignedApproval(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := ApproveWithReason(context.Background(), dir, ar.Token, "checked", testKey); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, testPub); err != nil {
		t.Fatalf("Verify = %v", err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, nil); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("Verify without a public key = %v, want ErrUnsigned", err)
	}
}
