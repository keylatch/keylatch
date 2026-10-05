package approval

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDecisionRefusedWhenRecordChangedAfterReview(t *testing.T) {
	dir := t.TempDir()
	ar, err := RequestNew(context.Background(), dir, "agent", "read", "github-readonly", "benign", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	shown := Digest(ar)

	// The requester rewrites its record while the approver types the
	// passphrase.
	swapped := *ar
	swapped.Connection = "prod-db"
	swapped.Capability = "export"
	swapped.RequestHash = "attacker"
	mustWrite(t, dir, &swapped)

	for _, decideFn := range []func() error{
		func() error { return Approve(context.Background(), dir, ar.Token, shown, testKey) },
		func() error { return Deny(context.Background(), dir, ar.Token, shown, testKey) },
	} {
		if err := decideFn(); !errors.Is(err, ErrChanged) {
			t.Fatalf("decision on a changed record = %v, want ErrChanged", err)
		}
	}
	got, _ := Get(context.Background(), dir, ar.Token)
	if got.Status != StatusPending || got.Signature != "" {
		t.Fatalf("changed record was signed: %+v", got)
	}
	if err := Verify(context.Background(), dir, ar.Token, "attacker", testPub); err == nil {
		t.Fatal("swapped request verifies")
	}
}

func TestRequestNewCapsTTL(t *testing.T) {
	ar, err := RequestNew(context.Background(), t.TempDir(), "a", "c", "p", "h", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got := ar.ExpiresAt.Sub(ar.CreatedAt); got > MaxTTL {
		t.Fatalf("request TTL = %v, want at most %v", got, MaxTTL)
	}
}

func TestDecisionRefusesOverlongTTL(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	ar := &ApprovalRequest{Token: tok("long"), Actor: "a", Connection: "p", Capability: "c", RequestHash: "h",
		Status: StatusPending, CreatedAt: now, ExpiresAt: now.Add(365 * 24 * time.Hour)}
	mustWrite(t, dir, ar)
	if err := Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), testKey); !errors.Is(err, ErrTTLTooLong) {
		t.Fatalf("Approve of a year-long request = %v, want ErrTTLTooLong", err)
	}
}

func TestVerifyAllowsOneUse(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), testKey); err != nil {
		t.Fatal(err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, testPub); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := Verify(context.Background(), dir, ar.Token, ar.RequestHash, testPub); !errors.Is(err, ErrUsed) {
		t.Fatalf("second use = %v, want ErrUsed", err)
	}
	if pending, _ := Pending(context.Background(), dir); len(pending) != 0 {
		t.Fatalf("use marker listed as a request: %+v", pending)
	}
}

func TestVerifyRejectsStaleOrFutureDecision(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), testKey); err != nil {
		t.Fatal(err)
	}
	got, _ := Get(context.Background(), dir, ar.Token)
	for name, now := range map[string]time.Time{
		"after the use window": got.DecidedAt.Add(UseWindow + time.Minute),
		"before the decision":  got.DecidedAt.Add(-time.Minute),
	} {
		err := verifyWithClock(context.Background(), dir, ar.Token, ar.RequestHash, testPub, fakeClock{t: now})
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("%s: Verify = %v, want ErrExpired", name, err)
		}
	}
}
