package cli

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/customsecret"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/gateway/approval"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	"github.com/keylatch/keylatch/internal/vault"
	"github.com/spf13/cobra"
)

type secretAddInput struct {
	name                             string
	valueStdin                       bool
	ref                              string
	hosts, paths, methods            []string
	header, query, basic, baseURLEnv string
	replace                          bool
}

// lookupSecret finds an entry under the lock. Only "not found" means absent;
// any other error (an unreadable or corrupt rules file) aborts the caller
// before it writes anything.
func lookupSecret(tx customsecret.Tx, name string) (customsecret.Secret, bool, error) {
	e, err := tx.Find(name)
	switch {
	case err == nil:
		return e, true, nil
	case errors.Is(err, customsecret.ErrNotFound):
		return customsecret.Secret{}, false, nil
	}
	return customsecret.Secret{}, false, opFailed("read custom secrets: %v", err)
}

// canActivateDirectly reports whether the person running `secret add` can act
// as the approver: a terminal on stdin and the approver passphrase. The
// environment-based agent detection is not relied on alone, since it can be
// absent. The second result explains a fallback to a pending proposal.
func canActivateDirectly() (bool, string, error) {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return false, "this is an agent session", nil
	}
	if !interactiveStdin() {
		return false, "stdin is not a terminal", nil
	}
	if _, err := approval.LoadApproverKey(approverKeyPath(llmcontext.DefaultLookup)); errors.Is(err, approval.ErrNoApproverKey) {
		return false, "no approver passphrase is set (run: keylatch approve init)", nil
	}
	key, err := unlockApprover("secret add", "KL-4124", "KL-4125")
	if err != nil {
		return false, "", err
	}
	clear(key)
	return true, "", nil
}

// runSecretAdd adds or replaces a custom secret. When the person at the
// terminal proves they are the approver, the change is live at once; otherwise
// it is only proposed: its value waits at the pending path, which the gateway
// never reads, until `secret approve`.
func runSecretAdd(c *cobra.Command, in secretAddInput) error {
	if in.valueStdin && in.ref != "" || (!in.replace && !in.valueStdin && in.ref == "") {
		return NewUsageError("exactly one of --value-stdin or --ref is required (with --replace, neither keeps the stored value)")
	}
	injection, err := injectionFromFlags(in.header, in.query, in.basic)
	if err != nil {
		return err
	}
	sec := customsecret.Secret{
		Name: in.name, Hosts: in.hosts, Paths: in.paths, Methods: in.methods,
		Injection: injection, BaseURLEnv: in.baseURLEnv, CreatedAt: time.Now().UTC(),
	}
	if err := sec.Normalize(); err != nil {
		return NewUsageError("%v", err)
	}
	haveValue := in.valueStdin || in.ref != ""

	var value []byte
	switch {
	case !haveValue:
	case in.ref != "":
		scheme, refErr := customsecret.RefSchemeOf(in.ref)
		if refErr != nil {
			// The cause is not shown: a secret passed by mistake must not reach stderr.
			return NewUsageError("--ref must be an op://, aws-sm:// or hashivault:// reference (secret values are never accepted as arguments)")
		}
		sec.RefScheme = scheme
		value = []byte(strings.TrimSpace(in.ref))
	default:
		value, err = readSecretValue(c)
		if err != nil {
			return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
		}
		if err := customsecret.ValidateValue(value); err != nil {
			return NewUsageError("%v", err)
		}
	}
	defer clear(value)

	direct, why, err := canActivateDirectly()
	if err != nil {
		return err
	}

	// Refuse before storing anything: an unaudited write would not be recorded.
	al, auditCleanup, err := requireAuditLogger("secret add")
	if err != nil {
		return err
	}
	defer auditCleanup()
	st := secretStore{ctx: audit.WithEmitter(c.Context(), audit.AsEmitter(al)), cfg: loadCLIConfig(c), env: llmcontext.DefaultLookup}
	file := paths.CustomSecrets(llmcontext.DefaultLookup)

	return customsecret.WithLock(file, func(tx customsecret.Tx) error {
		existing, exists, err := lookupSecret(tx, sec.Name)
		if err != nil {
			return err
		}
		switch {
		case in.replace && !exists:
			return NewUsageError("custom secret %q does not exist; add it without --replace", sec.Name)
		case !in.replace && exists:
			return NewUsageError("custom secret %q already exists (%s); use --replace to change it or remove it with: keylatch secret rm %s", sec.Name, existing.State(), sec.Name)
		case in.replace && !haveValue && !existing.Active():
			return NewUsageError("custom secret %q is not approved yet and has no active value; give --value-stdin or --ref", sec.Name)
		case !in.replace:
			if err := customsecret.Check(sec.Name); err != nil {
				return NewUsageError("%v", err)
			}
		}
		if !haveValue {
			sec.RefScheme = existing.RefScheme
		}
		if !direct {
			return proposeSecret(c, st, tx, sec, existing, exists, value, why)
		}
		return applySecret(c, st, tx, sec, existing, in.replace, value)
	})
}

// secretStore writes secret material through the audited vault layer.
type secretStore struct {
	ctx context.Context
	cfg config.Config
	env llmcontext.Lookup
}

func (s secretStore) set(path string, value []byte) error {
	return vault.Set(s.ctx, path, value, backend.Meta{Path: path, Backend: s.cfg.Backend, Version: 1}, s.cfg, s.env)
}

func (s secretStore) delete(path string) error {
	if err := vault.Delete(s.ctx, path, s.cfg, s.env); err != nil && !errors.Is(err, backend.ErrNotFound) {
		return err
	}
	return nil
}

func opFailed(format string, args ...any) error {
	return withExitCode(exitcode.OperationFailed, fmt.Errorf("[keylatch] error: "+format, args...))
}

// proposeSecret records a change as pending. The value goes to the pending
// path first, so the rules never point at a missing value. A proposal without a
// value keeps the active value and drops any value an earlier proposal left.
func proposeSecret(c *cobra.Command, st secretStore, tx customsecret.Tx, sec, existing customsecret.Secret, exists bool, value []byte, why string) error {
	pendingPath := customsecret.PendingPath(sec.Name)
	// Keep the value an earlier proposal left, so a failed save can put it back.
	var previous []byte
	if value != nil && exists && existing.NewValue {
		previous, _ = vault.Get(st.ctx, pendingPath, st.cfg, st.env)
		defer clear(previous)
	}
	if value != nil {
		if err := st.set(pendingPath, value); err != nil {
			return opFailed("store pending value: %v", err)
		}
	}
	entry := existing
	if !exists {
		entry = customsecret.Secret{Name: sec.Name, Status: customsecret.StatusPending, CreatedAt: sec.CreatedAt}
	}
	entry.Proposed, entry.NewValue = &sec, value != nil
	var err error
	if exists {
		err = tx.Replace(entry)
	} else {
		err = tx.Add(entry)
	}
	if err != nil {
		if value != nil {
			if previous != nil {
				_ = st.set(pendingPath, previous)
			} else {
				_ = st.delete(pendingPath)
			}
		}
		return opFailed("save rule: %v", err)
	}
	if value == nil && exists && existing.NewValue {
		if err := st.delete(customsecret.PendingPath(sec.Name)); err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "warning: superseded pending value not removed: %v\n", err)
		}
	}
	fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret proposed: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
	fmt.Fprintf(c.OutOrStdout(), "  pending owner approval (%s); it is not served until the owner runs: keylatch secret approve %s\n", why, sec.Name)
	return nil
}

// applySecret makes the change live; the person running it proved they are the approver.
func applySecret(c *cobra.Command, st secretStore, tx customsecret.Tx, sec, existing customsecret.Secret, replace bool, value []byte) error {
	valuePath := customsecret.ValuePath(sec.Name)
	// The value is written before the rules so a failure never leaves rules without a value.
	if value != nil {
		if err := st.set(valuePath, value); err != nil {
			return opFailed("store value: %v", err)
		}
	}
	if replace {
		if err := tx.Replace(sec); err != nil {
			return opFailed("save rule: %v", err)
		}
		if existing.Proposed != nil && existing.NewValue {
			if err := st.delete(customsecret.PendingPath(sec.Name)); err != nil {
				fmt.Fprintf(c.ErrOrStderr(), "warning: superseded pending value not removed: %v\n", err)
			}
		}
		fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret replaced: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
		fmt.Fprintln(c.OutOrStdout(), "  restart the gateway to serve the new rules")
		return nil
	}
	if err := tx.Add(sec); err != nil {
		// Under the lock no entry existed, so the value just written belongs to this call.
		if delErr := st.delete(valuePath); delErr != nil {
			return opFailed("save rule: %v (stored value could not be removed: %v)", err, delErr)
		}
		return opFailed("save rule: %v", err)
	}
	fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret added: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
	fmt.Fprintf(c.OutOrStdout(), "  gateway path: /sdk/%s/v1/<path>  (restart the gateway to serve it)\n", sec.Name)
	return nil
}

// printProposal shows exactly what approving would activate. A stored value is
// never printed, only its size; a reference is printed because it is a locator
// and not a credential.
func printProposal(w io.Writer, e customsecret.Secret, pv []byte) {
	p := *e.Proposed
	fmt.Fprintf(w, "Custom secret %s: %s\n", displaySafe(e.Name), e.State())
	fmt.Fprintf(w, "  hosts:      %s (requests to /sdk/%s/v1/... go to the first)\n", displaySafe(strings.Join(p.Hosts, ", ")), displaySafe(e.Name))
	fmt.Fprintf(w, "  paths:      %s\n", displaySafe(strings.Join(p.Paths, ", ")))
	fmt.Fprintf(w, "  methods:    %s\n", displaySafe(strings.Join(p.Methods, ", ")))
	injection := p.Kind()
	if p.Injection.Format != "" {
		injection += " = " + p.Injection.Format
	}
	fmt.Fprintf(w, "  injection:  %s\n", displaySafe(injection))
	if p.BaseURLEnv != "" {
		fmt.Fprintf(w, "  base url:   $%s is set to the gateway URL in 'keylatch run'\n", displaySafe(p.BaseURLEnv))
	}
	switch {
	case !e.NewValue:
		fmt.Fprintln(w, "  value:      unchanged (the active value is kept)")
	case p.RefScheme != "":
		fmt.Fprintf(w, "  value:      reference %s\n", displaySafe(string(pv)))
	default:
		fmt.Fprintf(w, "  value:      stored value, %d bytes\n", len(pv))
	}
}

// decideSecret runs the steps approve and reject share. The pending value is
// read once and shown before the passphrase prompt; after the prompt, under the
// lock, the entry and the value are read again and the decision is abandoned if
// either changed while the prompt was open, so an agent cannot swap what the
// approver reviewed. act runs under the same lock with the reviewed value.
func decideSecret(c *cobra.Command, verb, name string, act func(tx customsecret.Tx, st secretStore, e customsecret.Secret, pv []byte) error) error {
	if err := requireHumanApprover("secret "+verb, "KL-4122", "KL-4123"); err != nil {
		return err
	}
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	e, err := customsecret.Find(file, name)
	if err != nil {
		return withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
	}
	if e.Proposed == nil {
		return NewUsageError("custom secret %q has nothing pending", name)
	}
	// The stored form is what the recheck compares against; Normalize below
	// rewrites the proposal in place, so keep a copy of it as read.
	stored := e
	storedProposal := *e.Proposed
	stored.Proposed = &storedProposal
	// A broken proposal must stay rejectable.
	if verb != "reject" {
		if err := e.Proposed.Normalize(); err != nil {
			return NewUsageError("the pending change is invalid: %v; reject it", err)
		}
	}
	al, cleanup, err := requireAuditLogger("secret " + verb)
	if err != nil {
		return err
	}
	defer cleanup()
	st := secretStore{ctx: audit.WithEmitter(c.Context(), audit.AsEmitter(al)), cfg: loadCLIConfig(c), env: llmcontext.DefaultLookup}

	var pv []byte
	if e.NewValue {
		if pv, err = vault.Get(st.ctx, customsecret.PendingPath(name), st.cfg, st.env); err != nil {
			return opFailed("read pending value: %v", err)
		}
		defer clear(pv)
	}
	printProposal(c.ErrOrStderr(), e, pv)

	key, err := unlockApprover("secret "+verb, "KL-4124", "KL-4125")
	if err != nil {
		return err
	}
	clear(key)

	return customsecret.WithLock(file, func(tx customsecret.Tx) error {
		changed := NewSecurityBlock("secret %s: %q changed while the passphrase prompt was open; nothing was done. Review it again.", verb, name)
		cur, err := tx.Find(name)
		if err != nil || !sameEntry(cur, stored) {
			return changed
		}
		if e.NewValue {
			now, err := vault.Get(st.ctx, customsecret.PendingPath(name), st.cfg, st.env)
			if err != nil {
				return changed
			}
			same := subtle.ConstantTimeCompare(now, pv) == 1
			clear(now)
			if !same {
				return changed
			}
		}
		return act(tx, st, e, pv)
	})
}

// sameEntry compares two entries by their JSON form, which is what the rules file stores.
func sameEntry(a, b customsecret.Secret) bool {
	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(x, y)
}

func newSecretApproveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approve <name>",
		Short: "Approve a custom secret that was added or changed without approval",
		Long: `Activate the pending custom secret or change. The host, paths, methods,
injection rule and value source are printed first, then the approver passphrase
set with 'keylatch approve init' is required. Refused inside an LLM session.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			err := decideSecret(c, "approve", name, func(tx customsecret.Tx, st secretStore, e customsecret.Secret, pv []byte) error {
				// The value moves before the rules change, so approved rules always have a value.
				if e.NewValue {
					if err := st.set(customsecret.ValuePath(name), pv); err != nil {
						return opFailed("activate value: %v", err)
					}
					if err := st.delete(customsecret.PendingPath(name)); err != nil {
						return opFailed("remove pending value: %v", err)
					}
				}
				active := *e.Proposed
				if err := tx.Replace(active); err != nil {
					return opFailed("save rule: %v", err)
				}
				return nil
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret approved: %s (restart the gateway to serve it)\n", name)
			return nil
		},
	}
}

func newSecretRejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <name>",
		Short: "Reject a custom secret that was added or changed without approval",
		Long: `Discard the pending custom secret or change and its pending value. A secret
that was never approved is removed; an active secret keeps serving unchanged.
Requires the approver passphrase. Refused inside an LLM session.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			err := decideSecret(c, "reject", name, func(tx customsecret.Tx, st secretStore, e customsecret.Secret, _ []byte) error {
				if err := st.delete(customsecret.PendingPath(name)); err != nil {
					return opFailed("delete pending value: %v", err)
				}
				var err error
				if e.Active() {
					e.Proposed, e.NewValue = nil, false
					err = tx.Replace(e)
				} else {
					err = tx.Remove(name)
				}
				if err != nil {
					return opFailed("%v", err)
				}
				return nil
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret change rejected: %s\n", name)
			return nil
		},
	}
}
