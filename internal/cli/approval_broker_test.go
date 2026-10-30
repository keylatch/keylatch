package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/testutil"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

type approvalBrokerFunc func(context.Context, brokerapi.Request) (brokerapi.Response, error)

func (f approvalBrokerFunc) CallContext(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
	return f(ctx, req)
}

func useApprovalTestBroker(t *testing.T, call approvalBrokerFunc) {
	t.Helper()
	testutil.ClearLLMSessionEnv(t)
	t.Setenv("KEYLATCH_SOCKET", "")
	t.Setenv("KEYLATCH_APPROVALS_DIR", t.TempDir())
	withInteractiveStdin(t, true)
	oldInstalled, oldDial := brokerInstalled, dialApprovalBroker
	brokerInstalled = func(llmcontext.Lookup) bool { return true }
	dialApprovalBroker = func(llmcontext.Lookup) (approvalBrokerCaller, error) { return call, nil }
	t.Cleanup(func() { brokerInstalled, dialApprovalBroker = oldInstalled, oldDial })
}

func brokerApprovalEntry() brokerapi.ApprovalEntry {
	return brokerapi.ApprovalEntry{Token: "apv_" + strings.Repeat("a", 32), Digest: strings.Repeat("b", 64), Actor: "agent", Connection: "production", Capability: "run:D5", Summary: "argv: [\"deploy\", \"--production\"]\nhosts: [\"example.test\"]\nTTL: 1m", Status: "pending", CreatedAt: time.Now().Add(-time.Second), ExpiresAt: time.Now().Add(time.Minute)}
}

func TestApprovalCommandsUseBrokerReviewedDigest(t *testing.T) {
	for _, action := range []string{"approve", "deny"} {
		t.Run(action, func(t *testing.T) {
			entry := brokerApprovalEntry()
			var stdout, stderr bytes.Buffer
			calls := 0
			useApprovalTestBroker(t, func(ctx context.Context, req brokerapi.Request) (brokerapi.Response, error) {
				calls++
				_, bounded := ctx.Deadline()
				require.True(t, bounded)
				if calls == 1 {
					require.Equal(t, brokerapi.OpApprovalList, req.Op)
					return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{entry}}, nil
				}
				require.Equal(t, brokerapi.OpApprovalDecide, req.Op)
				require.Equal(t, &brokerapi.ApprovalDecision{Token: entry.Token, Digest: entry.Digest, Decision: action, Reason: "reviewed"}, req.Approval)
				require.Contains(t, stderr.String(), entry.Summary)
				require.Contains(t, stderr.String(), entry.Digest)
				return brokerapi.Response{OK: true}, nil
			})
			cmd := newApproveCmd()
			if action == "deny" {
				cmd = newDenyCmd()
			}
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)
			cmd.SetArgs([]string{entry.Token, "--reason", "reviewed", "--json"})
			require.NoError(t, cmd.ExecuteContext(t.Context()))
			require.Equal(t, 2, calls)
			var out approveOutput
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &out))
			require.Equal(t, entry.Token, out.Token)
			if action == "approve" {
				require.Equal(t, "approved", out.Status)
			} else {
				require.Equal(t, "denied", out.Status)
			}
		})
	}
}

func TestApprovalBrokerRefusalNeverReportsSuccess(t *testing.T) {
	entry := brokerApprovalEntry()
	useApprovalTestBroker(t, func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
		if req.Op == brokerapi.OpApprovalList {
			return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{entry}}, nil
		}
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "reviewed request changed"}, nil
	})
	cmd := newApproveCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{entry.Token, "--json"})
	err := cmd.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "reviewed request changed")
	require.NotContains(t, out.String(), `"approved"`)
}

func TestApprovalBrokerListPreservesCLIShape(t *testing.T) {
	entry := brokerApprovalEntry()
	useApprovalTestBroker(t, func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
		require.Equal(t, brokerapi.OpApprovalList, req.Op)
		return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{entry}}, nil
	})
	cmd := newApproveListCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--json"})
	require.NoError(t, cmd.ExecuteContext(t.Context()))
	var entries []approveListEntry
	require.NoError(t, json.Unmarshal(out.Bytes(), &entries))
	require.Len(t, entries, 1)
	require.Equal(t, entry.Token, entries[0].Token)
	require.Equal(t, entry.Connection, entries[0].Provider)
}

func TestApprovalBrokerFailureDoesNotReadLocalState(t *testing.T) {
	useApprovalTestBroker(t, func(context.Context, brokerapi.Request) (brokerapi.Response, error) {
		return brokerapi.Response{}, errors.New("broker offline")
	})
	for _, cmd := range []*cobra.Command{newApproveListCmd(), newApproveCmd(), newDenyCmd()} {
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		if cmd.Name() != "list" {
			cmd.SetArgs([]string{brokerApprovalEntry().Token})
		}
		require.ErrorContains(t, cmd.ExecuteContext(t.Context()), "broker offline")
	}
}

func TestDenyAllBrokerStopsOnRefusalAndReportsPartialCount(t *testing.T) {
	first := brokerApprovalEntry()
	second := first
	second.Token = "apv_" + strings.Repeat("c", 32)
	second.Digest = strings.Repeat("d", 64)
	decisions := 0
	useApprovalTestBroker(t, func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
		if req.Op == brokerapi.OpApprovalList {
			return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{first, second}}, nil
		}
		decisions++
		require.Equal(t, "deny", req.Approval.Decision)
		if decisions == 1 {
			require.Equal(t, first.Digest, req.Approval.Digest)
			return brokerapi.Response{OK: true}, nil
		}
		require.Equal(t, second.Digest, req.Approval.Digest)
		return brokerapi.Response{Code: brokerapi.CodeRefused, Error: "OS confirmation denied"}, nil
	})
	cmd := newDenyCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--all", "--yes"})
	err := cmd.ExecuteContext(t.Context())
	require.ErrorContains(t, err, "denied 1 request(s) before failure")
	require.ErrorContains(t, err, "OS confirmation denied")
	require.Equal(t, 2, decisions)
}

func TestBrokerApprovalStillRequiresHumanTerminal(t *testing.T) {
	calls := 0
	useApprovalTestBroker(t, func(context.Context, brokerapi.Request) (brokerapi.Response, error) {
		calls++
		return brokerapi.Response{OK: true}, nil
	})
	withInteractiveStdin(t, false)
	for _, cmd := range []*cobra.Command{newApproveCmd(), newDenyCmd()} {
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetErr(&bytes.Buffer{})
		cmd.SetArgs([]string{brokerApprovalEntry().Token})
		require.Error(t, cmd.ExecuteContext(t.Context()))
	}
	require.Zero(t, calls)
}

func TestDenyAllBrokerSkipsExpiredAndDecidedRequests(t *testing.T) {
	pending := brokerApprovalEntry()
	expired, decided := pending, pending
	expired.Token = "apv_" + strings.Repeat("c", 32)
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	decided.Token = "apv_" + strings.Repeat("d", 32)
	decided.Status = "approved"
	decisions := 0
	useApprovalTestBroker(t, func(_ context.Context, req brokerapi.Request) (brokerapi.Response, error) {
		if req.Op == brokerapi.OpApprovalList {
			return brokerapi.Response{OK: true, Approvals: []brokerapi.ApprovalEntry{expired, decided, pending}}, nil
		}
		decisions++
		require.Equal(t, pending.Token, req.Approval.Token)
		return brokerapi.Response{OK: true}, nil
	})
	cmd := newDenyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--all", "--yes", "--json"})
	require.NoError(t, cmd.ExecuteContext(t.Context()))
	var result denyAllOutput
	require.NoError(t, json.Unmarshal(out.Bytes(), &result))
	require.Equal(t, denyAllOutput{DeniedCount: 1, RequestIDs: []string{pending.Token}}, result)
	require.Equal(t, 1, decisions)
}
