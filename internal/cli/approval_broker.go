package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/brokerapi"
	"github.com/keylatch/keylatch/internal/control"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/spf13/cobra"
)

type approvalBrokerCaller interface {
	CallContext(context.Context, brokerapi.Request) (brokerapi.Response, error)
}

var dialApprovalBroker = func(env llmcontext.Lookup) (approvalBrokerCaller, error) {
	return control.NewClient(env)
}

func useApprovalBroker() bool {
	env := llmcontext.DefaultLookup
	return brokerInstalled(env) || env("KEYLATCH_SOCKET") != ""
}

func callApprovalBroker(ctx context.Context, client approvalBrokerCaller, req brokerapi.Request) (brokerapi.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := req.Validate(); err != nil {
		return brokerapi.Response{}, NewUsageError("%v", err)
	}
	resp, err := client.CallContext(ctx, req)
	if err != nil {
		return resp, withExitCodeOperation(string(req.Op), err)
	}
	if !resp.OK {
		return resp, brokerFailure(string(req.Op), resp)
	}
	return resp, nil
}

func listApprovalRequests(ctx context.Context) ([]*approval.ApprovalRequest, error) {
	if !useApprovalBroker() {
		return approval.List(ctx, paths.ApprovalsDir(llmcontext.DefaultLookup))
	}
	client, err := dialApprovalBroker(llmcontext.DefaultLookup)
	if err != nil {
		return nil, withExitCodeOperation("approve list", err)
	}
	resp, err := callApprovalBroker(ctx, client, brokerapi.Request{Op: brokerapi.OpApprovalList})
	if err != nil {
		return nil, err
	}
	requests := make([]*approval.ApprovalRequest, 0, len(resp.Approvals))
	for _, entry := range resp.Approvals {
		requests = append(requests, &approval.ApprovalRequest{Token: entry.Token, Connection: entry.Connection, Actor: entry.Actor, CreatedAt: entry.CreatedAt, ExpiresAt: entry.ExpiresAt, Status: entry.Status})
	}
	return requests, nil
}

func runBrokerApproval(c *cobra.Command, token, action, reason string, all, skipPrompt, useJSON bool) error {
	client, err := dialApprovalBroker(llmcontext.DefaultLookup)
	if err != nil {
		return withExitCodeOperation(action, err)
	}
	resp, err := callApprovalBroker(c.Context(), client, brokerapi.Request{Op: brokerapi.OpApprovalList})
	if err != nil {
		return err
	}
	selected := make([]brokerapi.ApprovalEntry, 0, len(resp.Approvals))
	for _, entry := range resp.Approvals {
		if all {
			if entry.Status == approval.StatusPending && entry.ExpiresAt.After(time.Now()) {
				selected = append(selected, entry)
			}
		} else if entry.Token == token {
			if err := undecided(&approval.ApprovalRequest{Status: entry.Status, ExpiresAt: entry.ExpiresAt}); err != nil {
				if action == "deny" {
					return denyError(token, err)
				}
				return approveError(token, err)
			}
			selected = append(selected, entry)
		}
	}
	if !all && len(selected) == 0 {
		if action == "deny" {
			return denyError(token, approval.ErrNotFound)
		}
		return approveError(token, approval.ErrNotFound)
	}
	if all && !skipPrompt && len(selected) > 0 {
		fmt.Fprintf(c.ErrOrStderr(), "Deny all %d pending approvals? [y/N] ", len(selected))
		line, _ := bufio.NewReader(c.InOrStdin()).ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "y" && line != "yes" {
			fmt.Fprintln(c.ErrOrStderr(), "Aborted.")
			return nil
		}
	}
	ids := make([]string, 0, len(selected))
	for _, entry := range selected {
		for _, line := range strings.Split(entry.Summary, "\n") {
			fmt.Fprintln(c.ErrOrStderr(), approval.DisplaySafe(line))
		}
		fmt.Fprintf(c.ErrOrStderr(), "reviewed digest: %s\n", approval.DisplaySafe(entry.Digest))
		req := brokerapi.Request{Op: brokerapi.OpApprovalDecide, Approval: &brokerapi.ApprovalDecision{Token: entry.Token, Digest: entry.Digest, Decision: action, Reason: reason}}
		if _, err := callApprovalBroker(c.Context(), client, req); err != nil {
			if all {
				return fmt.Errorf("deny --all: denied %d request(s) before failure at %s: %w", len(ids), entry.Token, err)
			}
			return err
		}
		ids = append(ids, entry.Token)
	}
	if all {
		if useJSON {
			return json.NewEncoder(c.OutOrStdout()).Encode(denyAllOutput{DeniedCount: len(ids), RequestIDs: ids})
		}
		fmt.Fprintf(c.OutOrStdout(), "denied %d approval(s).\n", len(ids))
		return nil
	}
	status := "approved"
	if action == "deny" {
		status = "denied"
	}
	if useJSON {
		return json.NewEncoder(c.OutOrStdout()).Encode(approveOutput{Token: token, Status: status, Reason: reason, Message: fmt.Sprintf("approval %q marked as %s", token, status)})
	}
	fmt.Fprintf(c.OutOrStdout(), "%s: %s\n", status, token)
	if reason != "" {
		fmt.Fprintf(c.OutOrStdout(), "reason: %s\n", displaySafe(reason))
	}
	return nil
}
