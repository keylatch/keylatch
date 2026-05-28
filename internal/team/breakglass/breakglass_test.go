package breakglass_test

import (
	"context"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/team"
	"github.com/keylatch/keylatch/internal/team/breakglass"
)

func newMember(id string) team.Member {
	return team.Member{
		ID:     id,
		HMAC:   "hmac-" + id,
		Role:   team.RoleDeveloper,
		Status: team.MemberActive,
	}
}

func TestOpen_LLMSessionBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := breakglass.WithLLMSession(context.Background())
	member := newMember("alice")

	_, err := breakglass.Open(ctx, member, "reason")
	if err != breakglass.ErrLLMSessionBlocked {
		t.Errorf("Open in LLM session: got %v, want ErrLLMSessionBlocked", err)
	}
}

func TestRateLimit_ThreeOpensAllowed_FourthBlocked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()

	// Test rate limit independently using bob.
	// Open 3 times without closing to avoid cooling period (open doesn't set LastClose).
	// M-10: removed the dead loop that only ran one iteration due to unconditional break.
	member2 := newMember("bob")

	for i := 0; i < 3; i++ {
		_, err := breakglass.Open(ctx, member2, "reason")
		if err != nil {
			t.Fatalf("Open #%d for rate-limit test: %v", i+1, err)
		}
	}

	// 4th open should fail with rate limit exceeded.
	_, err := breakglass.Open(ctx, member2, "4th attempt")
	if err != breakglass.ErrRateLimitExceeded {
		t.Errorf("4th open: got %v, want ErrRateLimitExceeded", err)
	}
}

func TestCoolingPeriod_Enforced(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	member := newMember("carol")

	// Open then immediately close.
	req, err := breakglass.Open(ctx, member, "emergency")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := breakglass.Close(ctx, req, member); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Immediately re-opening should fail with cooling period error.
	_, err = breakglass.Open(ctx, member, "immediate reopen")
	if err != breakglass.ErrCoolingPeriod {
		t.Errorf("immediate reopen: got %v, want ErrCoolingPeriod", err)
	}
}

func TestClose_SetsStatusAndAuditData(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	member := newMember("dave")

	req, err := breakglass.Open(ctx, member, "test reason")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if req.Status != breakglass.BGOpen {
		t.Errorf("Status = %v, want BGOpen", req.Status)
	}

	if err := breakglass.Close(ctx, req, member); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if req.Status != breakglass.BGClosed {
		t.Errorf("Status after close = %v, want BGClosed", req.Status)
	}
	if req.ClosedAt == nil {
		t.Error("ClosedAt should be set after close")
	}
	if req.ClosedAt.After(time.Now().Add(time.Second)) {
		t.Error("ClosedAt is in the future")
	}
}

func TestFileBackedCounters_PersistAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("KEYLATCH_TEAM_DIR", dir)
	ctx := context.Background()
	member := newMember("eve")

	// Open twice; counters should be file-backed and survive between calls.
	for i := 0; i < 2; i++ {
		_, err := breakglass.Open(ctx, member, "test")
		if err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
	}

	// Check rate limit directly — should show 2 opens.
	if err := breakglass.CheckRateLimit(ctx, member); err != nil {
		t.Errorf("CheckRateLimit after 2 opens: got %v, want nil (under limit)", err)
	}

	// Open third time.
	_, err := breakglass.Open(ctx, member, "third")
	if err != nil {
		t.Fatalf("3rd Open: %v", err)
	}

	// Now rate limit should be exceeded.
	if err := breakglass.CheckRateLimit(ctx, member); err != breakglass.ErrRateLimitExceeded {
		t.Errorf("CheckRateLimit after 3 opens: got %v, want ErrRateLimitExceeded", err)
	}
}
