package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/exitcode"
)

type cdFakeBroker struct {
	grants    []*broker.Grant
	listErr   error
	dryRun    *broker.DryRunResult
	dryRunErr error
	revokeErr map[string]error
	revoked   []string
}

func (f *cdFakeBroker) ListGrants() ([]*broker.Grant, error) { return f.grants, f.listErr }
func (f *cdFakeBroker) DryRunExchange(_, _ string) (*broker.DryRunResult, error) {
	return f.dryRun, f.dryRunErr
}
func (f *cdFakeBroker) Revoke(id string) error {
	if err := f.revokeErr[id]; err != nil {
		return err
	}
	f.revoked = append(f.revoked, id)
	return nil
}
func (f *cdFakeBroker) RevokeAll(string) (int, error) { return 0, errors.New("unused") }

func cdUseBroker(t *testing.T, f *cdFakeBroker) {
	t.Helper()
	prev := brokerHandleFactory
	brokerHandleFactory = func() broker.BrokerHandle { return f }
	t.Cleanup(func() { brokerHandleFactory = prev })
}

var errCdOutOfProcess = fmt.Errorf("wrapped: %w", broker.ErrBrokerOutOfProcess)

func TestBrokerCommands_OutOfProcessIsSecurityBlock(t *testing.T) {
	cases := []struct {
		name string
		fake *cdFakeBroker
		run  func(t *testing.T) cdResult
	}{
		{"status", &cdFakeBroker{listErr: errCdOutOfProcess}, func(t *testing.T) cdResult { return cdExec(t, newBrokerStatusCmd(), nil) }},
		{"dry-run", &cdFakeBroker{dryRunErr: errCdOutOfProcess}, func(t *testing.T) cdResult {
			return cdExec(t, newBrokerDryRunCmd(), nil, "openai", "ls")
		}},
		{"revoke", &cdFakeBroker{revokeErr: map[string]error{"tok": errCdOutOfProcess}}, func(t *testing.T) cdResult {
			return cdExec(t, newBrokerRevokeCmd(), nil, "tok")
		}},
		{"revoke --all", &cdFakeBroker{listErr: errCdOutOfProcess}, func(t *testing.T) cdResult {
			return cdExec(t, newBrokerRevokeCmd(), nil, "--all", "--yes")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdUseBroker(t, tc.fake)
			r := tc.run(t)
			cdAssertCLIError(t, r.e, exitcode.SecurityBlock)
			if !strings.Contains(r.e.Error(), "not running in-process") {
				t.Fatalf("err %v", r.e)
			}
			if len(tc.fake.revoked) != 0 {
				t.Fatal("nothing may be revoked out of process")
			}
		})
	}
}

func TestBrokerCommands_UnexpectedErrorsAreInternal(t *testing.T) {
	boom := errors.New("disk on fire")
	cases := []struct {
		name string
		fake *cdFakeBroker
		args []string
		cmd  string
	}{
		{"status", &cdFakeBroker{listErr: boom}, nil, "status"},
		{"dry-run", &cdFakeBroker{dryRunErr: boom}, []string{"openai", "ls"}, "dry-run"},
		{"revoke", &cdFakeBroker{revokeErr: map[string]error{"tok": boom}}, []string{"tok"}, "revoke"},
		{"revoke --all list", &cdFakeBroker{listErr: boom}, []string{"--all", "--yes"}, "revoke"},
		{"revoke --all item", &cdFakeBroker{
			grants:    []*broker.Grant{{ScopedTokenID: "a"}, {ScopedTokenID: "b"}},
			revokeErr: map[string]error{"a": boom},
		}, []string{"--all", "--yes"}, "revoke"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cdUseBroker(t, tc.fake)
			cmd := newBrokerStatusCmd()
			switch tc.cmd {
			case "dry-run":
				cmd = newBrokerDryRunCmd()
			case "revoke":
				cmd = newBrokerRevokeCmd()
			}
			r := cdExec(t, cmd, nil, tc.args...)
			cdAssertCLIError(t, r.e, exitCodeInternalError)
			if !strings.Contains(r.e.Error(), "disk on fire") {
				t.Fatalf("err %v must carry cause", r.e)
			}
			if len(tc.fake.revoked) != 0 {
				t.Fatalf("revocation must stop at the first hard failure, revoked %v", tc.fake.revoked)
			}
		})
	}
}

func TestBrokerDryRun_ProviderWithoutBrokerConfig(t *testing.T) {
	cdUseBroker(t, &cdFakeBroker{dryRunErr: fmt.Errorf("x: %w", broker.ErrProviderNoBrokerConfig)})
	r := cdExec(t, newBrokerDryRunCmd(), nil, "plainapi", "ls")
	cdAssertCLIError(t, r.e, exitcode.UserError)
	if !strings.Contains(r.e.Error(), `provider "plainapi" has no broker configuration`) {
		t.Fatalf("err %v", r.e)
	}
}

func TestBrokerDryRun_TableJoinsScopesAndGlobalJSON(t *testing.T) {
	res := &broker.DryRunResult{Provider: "github", ScopesRequested: []string{"repo", "read:org"},
		ScopedTokenTTL: 15 * time.Minute, PolicyDecision: "allow", Reason: "rule r1"}
	cdUseBroker(t, &cdFakeBroker{dryRun: res})
	r := cdExec(t, newBrokerDryRunCmd(), nil, "github", "gh pr list")
	if r.e != nil || !strings.Contains(r.out, "repo, read:org") || !strings.Contains(r.out, "15m0s") {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}

	r = cdExec(t, cdWithJSONRoot(newBrokerDryRunCmd()), nil, "--json", "dry-run", "github", "gh pr list")
	var got map[string]any
	if err := json.Unmarshal([]byte(r.out), &got); err != nil {
		t.Fatalf("global --json must produce JSON: %v %q", err, r.out)
	}
}

func TestBrokerRevoke_TextAndGlobalJSON(t *testing.T) {
	f := &cdFakeBroker{}
	cdUseBroker(t, f)
	r := cdExec(t, newBrokerRevokeCmd(), nil, "tok-1")
	if r.e != nil || strings.TrimSpace(r.out) != "Revoked token tok-1." {
		t.Fatalf("err=%v out=%q", r.e, r.out)
	}
	r = cdExec(t, cdWithJSONRoot(newBrokerRevokeCmd()), nil, "--json", "revoke", "tok-2")
	var got brokerRevokeOutput
	if err := json.Unmarshal([]byte(r.out), &got); err != nil || got.TokenID != "tok-2" || got.Status != "revoked" {
		t.Fatalf("json: %v %q", err, r.out)
	}
	if strings.Join(f.revoked, ",") != "tok-1,tok-2" {
		t.Fatalf("revoked %v", f.revoked)
	}
}

func TestBrokerRevokeAll_EmptyAndRaces(t *testing.T) {
	cdUseBroker(t, &cdFakeBroker{})
	r := cdExec(t, newBrokerRevokeCmd(), nil, "--all", "--yes")
	if r.e != nil || strings.TrimSpace(r.out) != "No active tokens to revoke." {
		t.Fatalf("empty text: err=%v out=%q", r.e, r.out)
	}
	r = cdExec(t, newBrokerRevokeCmd(), nil, "--all", "--json")
	var empty brokerRevokeAllOutput
	if err := json.Unmarshal([]byte(r.out), &empty); err != nil || empty.RevokedCount != 0 || empty.TokenIDs == nil {
		t.Fatalf("empty json: %v %q", err, r.out)
	}

	gone := fmt.Errorf("x: %w", broker.ErrTokenNotFound)
	f := &cdFakeBroker{
		grants:    []*broker.Grant{{ScopedTokenID: "a"}, {ScopedTokenID: "b"}},
		revokeErr: map[string]error{"a": gone},
	}
	cdUseBroker(t, f)
	r = cdExec(t, newBrokerRevokeCmd(), nil, "--all", "--yes")
	if r.e != nil || strings.TrimSpace(r.out) != "Revoked 1 token(s). (1 already expired, skipped)" {
		t.Fatalf("race text: err=%v out=%q", r.e, r.out)
	}

	f2 := &cdFakeBroker{grants: []*broker.Grant{{ScopedTokenID: "a"}}, revokeErr: map[string]error{"a": gone}}
	cdUseBroker(t, f2)
	r = cdExec(t, newBrokerRevokeCmd(), nil, "--all", "--json")
	var all brokerRevokeAllOutput
	if err := json.Unmarshal([]byte(r.out), &all); err != nil || all.RevokedCount != 0 || all.TokenIDs == nil {
		t.Fatalf("all-raced json must report an empty list: %v %q", err, r.out)
	}
}
