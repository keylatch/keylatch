package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/spf13/cobra"
)

// cdApprovals isolates paths, marks stdin as an interactive terminal and
// returns the approvals dir.
func cdApprovals(t *testing.T) string {
	t.Helper()
	dir := cdIsolate(t)
	ad := filepath.Join(dir, "approvals")
	t.Setenv("KEYLATCH_APPROVALS_DIR", ad)
	withInteractiveStdin(t, true)
	return ad
}

func cdNewApproval(t *testing.T, ad string) string {
	t.Helper()
	ar, err := approval.RequestNew(context.Background(), ad, "agent", "inject", "openai", "h", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return ar.Token
}

func cdReadApproval(t *testing.T, ad, tok string) approval.ApprovalRequest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(ad, tok+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var ar approval.ApprovalRequest
	if err := json.Unmarshal(b, &ar); err != nil {
		t.Fatal(err)
	}
	return ar
}

func cdRewriteApproval(t *testing.T, ad, tok string, mut func(*approval.ApprovalRequest)) {
	t.Helper()
	ar := cdReadApproval(t, ad, tok)
	mut(&ar)
	b, _ := json.Marshal(ar)
	if err := os.WriteFile(filepath.Join(ad, tok+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cdAssertCLIError(t *testing.T, err error, code int) {
	t.Helper()
	var ce *CLIError
	if !errors.As(err, &ce) || ce.Code != code {
		t.Fatalf("err = %v (%T), want CLIError code %d", err, err, code)
	}
}

func TestApproveDeny_RefusedInAgentSessionLeavesRequestPending(t *testing.T) {
	for name, ctor := range map[string]func() *cobra.Command{"approve": newApproveCmd, "deny": newDenyCmd} {
		t.Run(name, func(t *testing.T) {
			ad := cdApprovals(t)
			tok := cdNewApproval(t, ad)
			t.Setenv("CLAUDECODE", "1")
			r := cdExec(t, ctor(), nil, tok)
			assertSecurityBlock(t, r.e)
			if !strings.Contains(r.err, "not permitted inside an LLM session") {
				t.Fatalf("stderr %q missing refusal", r.err)
			}
			assertStillPending(t, ad, tok)
		})
	}
	t.Run("deny --all", func(t *testing.T) {
		ad := cdApprovals(t)
		tok := cdNewApproval(t, ad)
		t.Setenv("CURSOR_AGENT", "1")
		r := cdExec(t, newDenyCmd(), nil, "--all", "--yes")
		assertSecurityBlock(t, r.e)
		assertStillPending(t, ad, tok)
	})
}

func TestApproveDeny_TerminalStates(t *testing.T) {
	type tc struct {
		name   string
		mut    func(*approval.ApprovalRequest)
		code   int
		marker string
	}
	cases := []tc{
		{"expired pending", func(a *approval.ApprovalRequest) { a.ExpiresAt = time.Now().Add(-time.Minute) }, exitcode.UserError, "TTL has elapsed"},
		{"marked expired", func(a *approval.ApprovalRequest) { a.Status = approval.StatusExpired }, exitcode.UserError, "TTL has elapsed"},
		{"already denied", func(a *approval.ApprovalRequest) { a.Status = approval.StatusDenied }, exitcode.UserError, "already been approved or denied"},
		{"already approved", func(a *approval.ApprovalRequest) { a.Status = approval.StatusApproved }, exitcode.UserError, "already been approved or denied"},
	}
	for _, cmdName := range []string{"approve", "deny"} {
		for _, c := range cases {
			t.Run(cmdName+"/"+c.name, func(t *testing.T) {
				ad := cdApprovals(t)
				tok := cdNewApproval(t, ad)
				cdRewriteApproval(t, ad, tok, c.mut)
				before := cdReadApproval(t, ad, tok)
				ctor := newApproveCmd
				if cmdName == "deny" {
					ctor = newDenyCmd
				}
				r := cdExec(t, ctor(), nil, tok)
				cdAssertCLIError(t, r.e, c.code)
				if !strings.Contains(r.err, c.marker) {
					t.Fatalf("stderr %q missing %q", r.err, c.marker)
				}
				if after := cdReadApproval(t, ad, tok); after.Status != before.Status {
					t.Fatalf("status changed %q -> %q on a refused decision", before.Status, after.Status)
				}
			})
		}
	}
}

func TestApproveDeny_UnreadableRecordIsTreatedAsMissing(t *testing.T) {
	for name, ctor := range map[string]func() *cobra.Command{"approve": newApproveCmd, "deny": newDenyCmd} {
		t.Run(name, func(t *testing.T) {
			ad := cdApprovals(t)
			if err := os.MkdirAll(ad, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ad, "apv_broken.json"), []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
			r := cdExec(t, ctor(), nil, "apv_broken")
			cdAssertCLIError(t, r.e, exitcode.Missing)
		})
	}
}

func TestDeny_UnknownTokenAndMissingArg(t *testing.T) {
	cdApprovals(t)
	r := cdExec(t, newDenyCmd(), nil, "apv_nope")
	cdAssertCLIError(t, r.e, exitcode.Missing)
	if !strings.Contains(r.err, "not found") {
		t.Fatalf("stderr %q", r.err)
	}
	r = cdExec(t, newDenyCmd(), nil)
	if r.e == nil || !strings.Contains(r.e.Error(), "requires a <token> argument or --all") {
		t.Fatalf("err = %v", r.e)
	}
}

func TestApproveDeny_ReasonIsPrintedAndRecorded(t *testing.T) {
	for name, ctor := range map[string]func() *cobra.Command{"approve": newApproveCmd, "deny": newDenyCmd} {
		t.Run(name, func(t *testing.T) {
			ad := cdApprovals(t)
			withApprover(t)
			tok := cdNewApproval(t, ad)
			r := cdExec(t, ctor(), nil, tok, "--reason", "checked by hand")
			if r.e != nil {
				t.Fatal(r.e)
			}
			if !strings.Contains(r.out, "reason: checked by hand") {
				t.Fatalf("output %q missing reason", r.out)
			}
			ar := cdReadApproval(t, ad, tok)
			want := approval.StatusApproved
			if name == "deny" {
				want = approval.StatusDenied
			}
			if ar.Status != want || ar.Note != "checked by hand" {
				t.Fatalf("record = %+v", ar)
			}
		})
	}
}

func TestDenyAll_NothingPending(t *testing.T) {
	cdApprovals(t)
	r := cdExec(t, newDenyCmd(), nil, "--all", "--yes")
	if r.e != nil || strings.TrimSpace(r.out) != "No pending approvals." {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
	r = cdExec(t, newDenyCmd(), nil, "--all", "--yes", "--json")
	var got denyAllOutput
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || got.DeniedCount != 0 || got.RequestIDs == nil {
		t.Fatalf("json: %v %q", err, r.out)
	}
}

func TestApprovalsDirUnreadable(t *testing.T) {
	ad := cdApprovals(t)
	if err := os.WriteFile(ad, []byte("not a dir"), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := cdExec(t, newDenyCmd(), nil, "--all", "--yes"); r.e == nil || !strings.Contains(r.e.Error(), "deny --all:") {
		t.Fatalf("deny --all: err=%v", r.e)
	}
	if r := cdExec(t, newApproveListCmd(), nil); r.e == nil || !strings.Contains(r.e.Error(), "approve list:") {
		t.Fatalf("approve list: err=%v", r.e)
	}
}
