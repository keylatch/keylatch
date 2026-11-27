package cli

import (
	"context"
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

// runSecretAdd adds or replaces a custom secret. Outside an agent session the
// human is the approver and the change is live at once. Inside one the change
// is only proposed: its value waits at the pending path, which the gateway never
// reads, until `secret approve`.
func runSecretAdd(c *cobra.Command, in secretAddInput) error {
	proposeOnly := llmcontext.IsLLMSession(llmcontext.DefaultLookup)
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
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	existing, findErr := customsecret.Find(file, sec.Name)
	exists := findErr == nil
	haveValue := in.valueStdin || in.ref != ""
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

	var value []byte
	switch {
	case !haveValue:
		sec.RefScheme = existing.RefScheme
		if existing.Proposed != nil && existing.NewValue {
			sec.RefScheme = existing.Proposed.RefScheme
		}
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

	// Refuse before storing anything: an unaudited write would not be recorded.
	al, auditCleanup, err := requireAuditLogger("secret add")
	if err != nil {
		return err
	}
	defer auditCleanup()
	ctx := audit.WithEmitter(c.Context(), audit.AsEmitter(al))
	cfg := loadCLIConfig(c)
	st := secretStore{ctx: ctx, cfg: cfg, env: llmcontext.DefaultLookup}

	if proposeOnly {
		return proposeSecret(c, st, file, sec, existing, exists, value)
	}
	return applySecret(c, st, file, sec, existing, in.replace, value)
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

// proposeSecret records a change from an agent session as pending. The value
// goes to the pending path first, so the rules never point at a missing value.
func proposeSecret(c *cobra.Command, st secretStore, file string, sec, existing customsecret.Secret, exists bool, value []byte) error {
	newValue := value != nil || (exists && existing.NewValue)
	if value != nil {
		if err := st.set(customsecret.PendingPath(sec.Name), value); err != nil {
			return opFailed("store pending value: %v", err)
		}
	}
	entry := existing
	if !exists {
		entry = customsecret.Secret{Name: sec.Name, Status: customsecret.StatusPending, CreatedAt: sec.CreatedAt}
	}
	entry.Proposed, entry.NewValue = &sec, newValue
	var err error
	if exists {
		err = customsecret.Replace(file, entry)
	} else {
		err = customsecret.Add(file, entry)
	}
	if err != nil {
		if !exists && value != nil {
			_ = st.delete(customsecret.PendingPath(sec.Name))
		}
		return opFailed("save rule: %v", err)
	}
	fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret proposed: %s -> %s (%s, %s)\n", sec.Name, sec.Hosts[0], sec.Kind(), sec.Source())
	fmt.Fprintf(c.OutOrStdout(), "  pending owner approval; it is not served until the owner runs: keylatch secret approve %s\n", sec.Name)
	return nil
}

// applySecret makes the change live; the human running it is the approver.
func applySecret(c *cobra.Command, st secretStore, file string, sec, existing customsecret.Secret, replace bool, value []byte) error {
	valuePath := customsecret.ValuePath(sec.Name)
	// The value is written before the rules so a failure never leaves rules without a value.
	if value != nil {
		if err := st.set(valuePath, value); err != nil {
			return opFailed("store value: %v", err)
		}
	}
	if replace {
		if err := customsecret.Replace(file, sec); err != nil {
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
	if err := customsecret.Add(file, sec); err != nil {
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
// never printed; a reference is, because it is a locator and not a credential.
func printProposal(w io.Writer, st secretStore, e customsecret.Secret) error {
	p := *e.Proposed
	fmt.Fprintf(w, "Custom secret %s: %s\n", displaySafe(e.Name), e.State())
	fmt.Fprintf(w, "  hosts:      %s\n", displaySafe(strings.Join(p.Hosts, ", ")))
	fmt.Fprintf(w, "  paths:      %s\n", displaySafe(strings.Join(p.Paths, ", ")))
	methods := "any"
	if len(p.Methods) > 0 {
		methods = strings.Join(p.Methods, ", ")
	}
	fmt.Fprintf(w, "  methods:    %s\n", displaySafe(methods))
	injection := p.Kind()
	if p.Injection.Format != "" {
		injection += " = " + p.Injection.Format
	}
	fmt.Fprintf(w, "  injection:  %s\n", displaySafe(injection))
	switch {
	case !e.NewValue:
		fmt.Fprintln(w, "  value:      unchanged (the active value is kept)")
	case p.RefScheme != "":
		ref, err := vault.Get(st.ctx, customsecret.PendingPath(e.Name), st.cfg, st.env)
		if err != nil {
			return opFailed("read pending reference: %v", err)
		}
		fmt.Fprintf(w, "  value:      reference %s\n", displaySafe(string(ref)))
		clear(ref)
	default:
		fmt.Fprintln(w, "  value:      stored value")
	}
	return nil
}

// decideSecret runs the steps approve and reject share: a human at a terminal,
// the audit log, the summary and the approver passphrase.
func decideSecret(c *cobra.Command, verb, name string) (secretStore, customsecret.Secret, func(), error) {
	none := func() {}
	if err := requireHumanApprover("secret "+verb, "KL-4111", "KL-4112"); err != nil {
		return secretStore{}, customsecret.Secret{}, none, err
	}
	file := paths.CustomSecrets(llmcontext.DefaultLookup)
	e, err := customsecret.Find(file, name)
	if err != nil {
		return secretStore{}, e, none, withExitCode(exitcode.UserError, fmt.Errorf("[keylatch] error: %w", err))
	}
	if e.Proposed == nil {
		return secretStore{}, e, none, NewUsageError("custom secret %q has nothing pending", name)
	}
	if err := e.Proposed.Normalize(); err != nil {
		return secretStore{}, e, none, NewUsageError("the pending change is invalid: %v; reject it", err)
	}
	al, cleanup, err := requireAuditLogger("secret " + verb)
	if err != nil {
		return secretStore{}, e, none, err
	}
	st := secretStore{ctx: audit.WithEmitter(c.Context(), audit.AsEmitter(al)), cfg: loadCLIConfig(c), env: llmcontext.DefaultLookup}
	if err := printProposal(c.ErrOrStderr(), st, e); err != nil {
		cleanup()
		return st, e, none, err
	}
	key, err := unlockApprover("secret "+verb, "KL-4113", "KL-4114")
	if err != nil {
		cleanup()
		return st, e, none, err
	}
	clear(key)
	return st, e, cleanup, nil
}

func newSecretApproveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "approve <name>",
		Short: "Approve a custom secret an agent session added or changed",
		Long: `Activate the pending custom secret or change. The hosts, paths, methods,
injection rule and value source are printed first, then the approver passphrase
set with 'keylatch approve init' is required. Refused inside an LLM session.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			st, e, cleanup, err := decideSecret(c, "approve", name)
			if err != nil {
				return err
			}
			defer cleanup()

			// The value moves before the rules change, so approved rules always have a value.
			if e.NewValue {
				v, err := vault.Get(st.ctx, customsecret.PendingPath(name), st.cfg, st.env)
				if err != nil {
					return opFailed("read pending value: %v", err)
				}
				defer clear(v)
				if err := st.set(customsecret.ValuePath(name), v); err != nil {
					return opFailed("activate value: %v", err)
				}
				if err := st.delete(customsecret.PendingPath(name)); err != nil {
					return opFailed("remove pending value: %v", err)
				}
			}
			active := *e.Proposed
			active.CreatedAt = e.CreatedAt
			if err := customsecret.Replace(paths.CustomSecrets(llmcontext.DefaultLookup), active); err != nil {
				return opFailed("save rule: %v", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret approved: %s (restart the gateway to serve it)\n", name)
			return nil
		},
	}
}

func newSecretRejectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reject <name>",
		Short: "Reject a custom secret an agent session added or changed",
		Long: `Discard the pending custom secret or change and its pending value. A secret
that was never approved is removed; an active secret keeps serving unchanged.
Requires the approver passphrase. Refused inside an LLM session.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			name := args[0]
			st, e, cleanup, err := decideSecret(c, "reject", name)
			if err != nil {
				return err
			}
			defer cleanup()

			if err := st.delete(customsecret.PendingPath(name)); err != nil {
				return opFailed("delete pending value: %v", err)
			}
			file := paths.CustomSecrets(llmcontext.DefaultLookup)
			if e.Active() {
				e.Proposed, e.NewValue = nil, false
				err = customsecret.Replace(file, e)
			} else {
				err = customsecret.Remove(file, name)
			}
			if err != nil {
				return opFailed("%v", err)
			}
			fmt.Fprintf(c.OutOrStdout(), "[keylatch] secret change rejected: %s\n", name)
			return nil
		},
	}
}
