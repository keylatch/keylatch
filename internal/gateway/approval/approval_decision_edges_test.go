package approval

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func scSkipIfNoPerms(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func scReadOnlyDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func TestRequestNew_WriteFailureReturnsError(t *testing.T) {
	scSkipIfNoPerms(t)
	dir := t.TempDir()
	scReadOnlyDir(t, dir)
	_, err := RequestNew(context.Background(), dir, "a", "c", "conn", "h", time.Minute)
	if err == nil || !strings.Contains(err.Error(), "write tmp") {
		t.Fatalf("want write tmp error, got %v", err)
	}
}

func TestList_SkipsNoiseAndFailsOnUnreadableDir(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := List(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Token != ar.Token {
		t.Fatalf("List = %+v", got)
	}

	file := filepath.Join(dir, "notes.txt")
	if _, err := List(context.Background(), file); err == nil || !strings.Contains(err.Error(), "approval: open") {
		t.Fatalf("want readdir error, got %v", err)
	}
}

func TestEffectiveStatus(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	clk := fakeClock{t: now}
	cases := []struct {
		status  string
		expires time.Time
		want    string
	}{
		{StatusPending, now.Add(-time.Second), StatusExpired},
		{StatusPending, now.Add(time.Second), StatusPending},
		{StatusApproved, now.Add(-time.Hour), StatusApproved},
		{StatusDenied, now.Add(-time.Hour), StatusDenied},
	}
	for _, tc := range cases {
		got := EffectiveStatus(&ApprovalRequest{Status: tc.status, ExpiresAt: tc.expires}, clk)
		if got != tc.want {
			t.Errorf("EffectiveStatus(%s, expires %v) = %s, want %s", tc.status, tc.expires.Sub(now), got, tc.want)
		}
	}
}

func TestExpireOldPending_EdgeCases(t *testing.T) {
	n, err := ExpireOldPending(context.Background(), filepath.Join(t.TempDir(), "absent"))
	if err != nil || n != 0 {
		t.Fatalf("missing dir: n=%d err=%v", n, err)
	}

	dir := t.TempDir()
	file := filepath.Join(dir, "f.json")
	if err := os.WriteFile(file, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ExpireOldPending(context.Background(), file); err == nil || !strings.Contains(err.Error(), "approval: open") {
		t.Fatalf("want readdir error, got %v", err)
	}
	n, err = expireOldPendingWithClock(dir, fakeClock{t: time.Now().Add(time.Hour)})
	if err != nil || n != 0 {
		t.Fatalf("corrupt-only dir: n=%d err=%v", n, err)
	}
}

func TestExpireOldPending_WriteFailureIsTolerated(t *testing.T) {
	scSkipIfNoPerms(t)
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	scReadOnlyDir(t, dir)
	n, err := expireOldPendingWithClock(dir, fakeClock{t: ar.ExpiresAt.Add(time.Minute)})
	if err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	back, err := readApprovalFile(filepath.Join(dir, ar.Token+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if back.Status != StatusPending {
		t.Fatalf("status changed despite write failure: %s", back.Status)
	}
}

func TestApproveAndDenyWithReason_PersistNote(t *testing.T) {
	dir := t.TempDir()
	a := makeRequest(t, dir)
	d := makeRequest(t, dir)
	if err := ApproveWithReason(context.Background(), dir, a.Token, shownOf(t, dir, a.Token), "looks fine", testKey); err != nil {
		t.Fatal(err)
	}
	if err := DenyWithReason(context.Background(), dir, d.Token, shownOf(t, dir, d.Token), "unexpected host", testKey); err != nil {
		t.Fatal(err)
	}
	ra, _ := readApprovalFile(filepath.Join(dir, a.Token+".json"))
	rd, _ := readApprovalFile(filepath.Join(dir, d.Token+".json"))
	if ra.Status != StatusApproved || ra.Note != "looks fine" {
		t.Fatalf("approved record: %+v", ra)
	}
	if rd.Status != StatusDenied || rd.Note != "unexpected host" {
		t.Fatalf("denied record: %+v", rd)
	}
	if err := Verify(context.Background(), dir, d.Token, "", testPub); err == nil {
		t.Fatal("denied approval verified")
	}
	if err := DenyWithReason(context.Background(), dir, a.Token, shownOf(t, dir, a.Token), "too late", testKey); !errors.Is(err, ErrAlreadyActed) {
		t.Fatalf("deny after approve: want ErrAlreadyActed, got %v", err)
	}
}

func TestUpdateStatus_SweptEntryCannotBeApproved(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	n, err := expireOldPendingWithClock(dir, fakeClock{t: ar.ExpiresAt.Add(time.Second)})
	if err != nil || n != 1 {
		t.Fatalf("sweep: n=%d err=%v", n, err)
	}
	err = Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), testKey)
	var ttl *ErrExpiredTTL
	if !errors.As(err, &ttl) {
		t.Fatalf("want ErrExpiredTTL, got %v", err)
	}
	if !errors.Is(err, ErrExpired) || !errors.Is(err, ErrAlreadyActed) {
		t.Fatal("ErrExpiredTTL must match ErrExpired and ErrAlreadyActed")
	}
	want := ar.ExpiresAt.UTC().Format(time.RFC3339)
	if !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "auto-denied") {
		t.Fatalf("message %q lacks expiry %s", err.Error(), want)
	}
	if errors.Is(err, ErrNotFound) {
		t.Fatal("ErrExpiredTTL must not match ErrNotFound")
	}
}

func TestVerify_ApprovedButExpiredRejectedEvenWithMatchingHash(t *testing.T) {
	dir := t.TempDir()
	ar := makeRequest(t, dir)
	if err := Approve(context.Background(), dir, ar.Token, shownOf(t, dir, ar.Token), testKey); err != nil {
		t.Fatal(err)
	}
	err := verifyWithClock(context.Background(), dir, ar.Token, ar.RequestHash, testPub, fakeClock{t: ar.ExpiresAt.Add(time.Nanosecond)})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestWriteApproval_Failures(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	occupied := tok("occupied")
	if err := os.MkdirAll(filepath.Join(dir, occupied+".json", "child"), 0o700); err != nil {
		t.Fatal(err)
	}
	err = writeApproval(root, &ApprovalRequest{Token: occupied})
	if err == nil || !strings.Contains(err.Error(), "rename") {
		t.Fatalf("want rename error, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, occupied+".json.tmp")); !os.IsNotExist(statErr) {
		t.Fatalf("tmp file left behind: %v", statErr)
	}

	blocked := tok("blocked")
	if err := os.Mkdir(filepath.Join(dir, blocked+".json.tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	err = writeApproval(root, &ApprovalRequest{Token: blocked})
	if err == nil || !strings.Contains(err.Error(), "write tmp") {
		t.Fatalf("want write tmp error, got %v", err)
	}

	if err := writeApproval(root, &ApprovalRequest{Token: "../escape"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound for an invalid token, got %v", err)
	}
}
