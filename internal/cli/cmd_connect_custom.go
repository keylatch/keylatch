package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/connections"
	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/spf13/cobra"
)

const customProvider = "custom"

type customConnectInput struct {
	Namespace string
	Hosts     []string
	Slots     []string
	Envs      []string
	Prefix    string
	MinLength int
	Fields    map[string][]byte
}

func callerKind(env llmcontext.Lookup) connections.CallerKind {
	if llmcontext.IsLLMSession(env) {
		return connections.CallerAgent
	}
	return connections.CallerHuman
}

func addCustomConnectFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.String("provider", "", "provider kind; \"custom\" declares the connection's own bindings")
	f.StringArray("host", nil, "custom: host[:port] the secret may be sent to (repeatable)")
	f.StringArray("slot", nil, "custom: request slot, e.g. header:Authorization:Bearer, query:name, basic:user (repeatable)")
	f.StringArray("env", nil, "custom: environment variable the child reads, NAME or field=NAME (repeatable)")
	f.String("placeholder-prefix", "", "custom: placeholder prefix the client library expects")
	f.Int("placeholder-min-length", registry.DefaultCustomMinLength, "custom: placeholder minimum length")
}

func connectCustomFromFlags(c *cobra.Command, name string) error {
	ctx := c.Context()
	cfg := loadCLIConfig(c)
	st := newDispatchedStore(cfg, llmcontext.DefaultLookup)
	f := c.Flags()

	in := customConnectInput{Fields: map[string][]byte{}}
	in.Namespace, _ = f.GetString("namespace")
	in.Hosts, _ = f.GetStringArray("host")
	in.Slots, _ = f.GetStringArray("slot")
	in.Envs, _ = f.GetStringArray("env")
	in.Prefix, _ = f.GetString("placeholder-prefix")
	in.MinLength, _ = f.GetInt("placeholder-min-length")

	fieldFlags, _ := f.GetStringArray("field")
	for _, kv := range fieldFlags {
		key, val, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			return NewUsageError("invalid --field format %q; expected name=value", kv)
		}
		data, err := customFieldValue(c, key, val)
		if err != nil {
			return err
		}
		in.Fields[key] = data
	}
	if stdinField, _ := f.GetString("stdin-field"); stdinField != "" {
		data, err := readFieldFromStdin(c.InOrStdin())
		if err != nil {
			return NewUsageError("reading stdin for field %q: %v", stdinField, err)
		}
		in.Fields[stdinField] = data
	}
	refs, _ := f.GetStringArray("provider-ref")
	if len(refs) > 0 {
		if err := resolveProviderRefs(ctx, refs, in.Fields); err != nil {
			return err
		}
	}

	var em audit.Emitter
	if al, cleanup, err := OpenAuditLogger(); err == nil {
		defer cleanup()
		em = audit.AsEmitter(al)
	} else {
		fmt.Fprintf(c.ErrOrStderr(), "warning: audit logger unavailable (%v) — binding change will not be audited\n", err)
	}
	return connectCustom(ctx, c.OutOrStdout(), st, name, in, callerKind(llmcontext.DefaultLookup), em)
}

func customFieldValue(c *cobra.Command, key, val string) ([]byte, error) {
	switch {
	case val == "@-":
		return readFieldFromStdin(c.InOrStdin())
	case val == "@prompt":
		if !stdinIsTTY() {
			return nil, NewUsageError("field %q requires a TTY for @prompt; use --field %s=@- to read from stdin", key, key)
		}
		return promptHidden(fmt.Sprintf("Enter %s", key))
	case looksLikeSensitive(val):
		return nil, NewInsecureArgv("field %q contains a sensitive value — use --field %s=@-, @prompt or --provider-ref", key, key)
	}
	return []byte(val), nil
}

func connectCustom(ctx context.Context, out io.Writer, st connections.Store, name string, in customConnectInput, kind connections.CallerKind, em audit.Emitter) error {
	fieldNames, exists, err := connections.CustomFields(ctx, st, in.Namespace, name)
	if err != nil {
		return err
	}
	if !exists {
		for f := range in.Fields {
			fieldNames = append(fieldNames, f)
		}
	}
	b, err := buildCustomBinding(in, fieldNames)
	if err != nil {
		return NewUsageError("%v", err)
	}

	change, err := connections.SaveCustom(ctx, name, connections.CustomOptions{
		Namespace: in.Namespace,
		Fields:    in.Fields,
		Binding:   b,
		Caller:    kind,
	}, st)
	switch {
	case errors.Is(err, connections.ErrBindingHumanOnly):
		emitBinding(ctx, em, audit.ActionBindingRefused, audit.OutcomeDenied, name, kind, change, change.Kind)
		return &CLIError{
			Class: "SecurityBlock",
			Code:  exitcode.SecurityBlock,
			Message: fmt.Sprintf("connect: %s a binding is human-only; run `keylatch connect %s --provider custom ...` from a terminal outside an agent session",
				map[string]string{connections.ChangeCreated: "creating", connections.ChangeWidened: "widening"}[change.Kind], name),
		}
	case err != nil:
		return &CLIError{Class: "OperationFailed", Code: exitcode.OperationFailed, Message: fmt.Sprintf("connect: %v", err)}
	}

	switch change.Kind {
	case connections.ChangeCreated:
		emitBinding(ctx, em, audit.ActionBindingCreated, audit.OutcomeOK, name, kind, change, "")
	case connections.ChangeWidened:
		emitBinding(ctx, em, audit.ActionBindingWidened, audit.OutcomeOK, name, kind, change, "")
	case connections.ChangeNarrowed:
		emitBinding(ctx, em, audit.ActionBindingNarrowed, audit.OutcomeOK, name, kind, change, "")
	}
	fmt.Fprintf(out, "v %s — custom binding %s (hosts: %s)\n", name, change.Kind, strings.Join(change.HostsAfter, ", "))
	return nil
}

func buildCustomBinding(in customConnectInput, fields []string) (registry.CustomBinding, error) {
	sole := ""
	if len(fields) == 1 {
		sole = fields[0]
	}
	b := registry.CustomBinding{
		Hosts: in.Hosts,
		Shape: registry.PlaceholderShape{Prefix: in.Prefix, MinLength: in.MinLength},
		Env:   map[string]string{},
	}
	for _, spec := range in.Slots {
		s, err := registry.ParseSlot(spec)
		if err != nil {
			return b, err
		}
		if s.Field == "" {
			s.Field = sole
		}
		if s.Field == "" {
			return b, fmt.Errorf("slot %q: name the secret field as field=%s", spec, spec)
		}
		s.Hosts = in.Hosts
		b.Slots = append(b.Slots, s)
	}
	for _, e := range in.Envs {
		field, name, ok := strings.Cut(e, "=")
		if !ok {
			field, name = sole, e
		}
		if field == "" {
			return b, fmt.Errorf("env %q: name the secret field as field=NAME", e)
		}
		b.Env[field] = name
	}
	return b, nil
}

func emitBinding(ctx context.Context, em audit.Emitter, action audit.Action, outcome audit.Outcome, name string, kind connections.CallerKind, c connections.BindingChange, attempted string) {
	if em == nil {
		return
	}
	extra := map[string]any{
		"connection":   name,
		"caller_kind":  string(kind),
		"hosts_before": c.HostsBefore,
		"hosts_after":  c.HostsAfter,
	}
	if attempted != "" {
		extra["attempted"] = attempted
	}
	_ = em.Emit(ctx, audit.Event{Action: action, Outcome: outcome, Extra: extra})
}
