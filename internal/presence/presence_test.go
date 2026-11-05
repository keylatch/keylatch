package presence_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/presence"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

type fakeMethod struct {
	err   error
	calls int
}

func (*fakeMethod) Name() string { return "fake" }
func (f *fakeMethod) Confirm(context.Context, presence.Action, string) error {
	f.calls++
	return f.err
}

func TestRequireNeedsTTY(t *testing.T) {
	r := presencetest.Approver()
	r.Terminal = func() bool { return false }
	asked := false
	r.Ask = func(presence.Action, string) (bool, error) { asked = true; return true, nil }

	_, err := r.Require(context.Background(), presence.ActionPolicyChange, "allow agent github")
	if !errors.Is(err, presence.ErrNoTTY) {
		t.Fatalf("err = %v, want ErrNoTTY", err)
	}
	if asked {
		t.Fatal("prompted without a terminal")
	}
}

func TestRequireDeniedByPlatform(t *testing.T) {
	r := presencetest.Approver()
	r.Platform = &fakeMethod{err: errors.New("authentication failed")}

	_, err := r.Require(context.Background(), presence.ActionPolicyChange, "allow agent github")
	if !errors.Is(err, presence.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestRequireDeclinedOnTerminal(t *testing.T) {
	r := presencetest.Approver()
	r.Ask = func(presence.Action, string) (bool, error) { return false, nil }
	if _, err := r.Require(context.Background(), presence.ActionUIAdmin, "ui admin"); !errors.Is(err, presence.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

func TestRequireRefusesAgentAncestry(t *testing.T) {
	r := presencetest.Approver()
	r.Ancestry = func() []llmcontext.Process {
		return []llmcontext.Process{{PID: 10, Names: []string{"claude"}}}
	}
	if _, err := r.Require(context.Background(), presence.ActionUIAdmin, "ui admin"); !errors.Is(err, presence.ErrAgentTerminal) {
		t.Fatalf("err = %v, want ErrAgentTerminal", err)
	}
}

func TestRequireUnavailablePlatformStillNeedsTerminal(t *testing.T) {
	r := presencetest.Approver()
	r.Platform = &fakeMethod{err: presence.ErrUnavailable}
	proof, err := r.Require(context.Background(), presence.ActionUIAdmin, "ui admin")
	if err != nil {
		t.Fatal(err)
	}
	if proof.Method != "tty" {
		t.Fatalf("method = %q, want tty", proof.Method)
	}
}

func TestRequireIssuesBoundProof(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	r := presencetest.Approver()
	r.Now = func() time.Time { return now }
	m := &fakeMethod{}
	r.Platform = m

	proof, err := r.Require(context.Background(), presence.ActionGatewayToken, " token for agent ")
	if err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 || proof.Method != "tty+fake" {
		t.Fatalf("calls=%d method=%q", m.calls, proof.Method)
	}
	if !proof.Covers(presence.ActionGatewayToken, "token for agent") {
		t.Fatal("proof does not cover the summary the human read")
	}
	if proof.Covers(presence.ActionGatewayToken, "token for everyone") || proof.Covers(presence.ActionPolicyChange, "token for agent") {
		t.Fatal("proof covers a different request")
	}
	if !proof.Fresh(now.Add(59*time.Second), time.Minute) || proof.Fresh(now.Add(61*time.Second), time.Minute) || proof.Fresh(now.Add(-time.Second), time.Minute) {
		t.Fatal("freshness window wrong")
	}
}

func TestRequireNeedsActionAndSummary(t *testing.T) {
	r := presencetest.Approver()
	if _, err := r.Require(context.Background(), "", "x"); err == nil {
		t.Fatal("empty action accepted")
	}
	if _, err := r.Require(context.Background(), presence.ActionUIAdmin, "  "); err == nil {
		t.Fatal("empty summary accepted")
	}
}

// No variable the caller sets can change the outcome: the package must not
// read the environment at all.
func TestNoEnvOverride(t *testing.T) {
	for _, k := range []string{"KEYLATCH_PRESENCE", "KEYLATCH_ALLOW_UNVERIFIED_SESSION", "CI", "KEYLATCH_NO_PRESENCE", "SKIP_PRESENCE"} {
		t.Setenv(k, "1")
	}
	r := presencetest.Approver()
	r.Terminal = func() bool { return false }
	if _, err := r.Require(context.Background(), presence.ActionUIAdmin, "ui admin"); !errors.Is(err, presence.ErrNoTTY) {
		t.Fatalf("err = %v, want ErrNoTTY", err)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, banned := range []string{"os.Getenv", "os.LookupEnv", "os.Environ", "ExpandEnv"} {
			if strings.Contains(string(src), banned) {
				t.Errorf("%s uses %s", f, banned)
			}
		}
	}
}
