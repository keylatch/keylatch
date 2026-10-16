package keyops

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
)

// Change describes an allowlist edit.
type Change struct {
	Connection string
	Field      string
	// Secret is the backend path of the key; required for a new field.
	Secret       string
	Operations   []string
	Algorithms   []string
	HostKeys     []string
	AgentDecrypt bool
	SSHAgent     bool
	// PresenceDigest identifies the human-presence proof an allow was made
	// under; it is recorded in the audit event.
	PresenceDigest string
}

// Admin edits the allowlist. Adding or widening is for humans only; removing
// is open to any caller, because it can only narrow what is permitted.
type Admin struct {
	store *Store
	audit audit.Emitter
}

// NewAdmin returns an Admin over store.
func NewAdmin(store *Store, emitter audit.Emitter) (*Admin, error) {
	if store == nil || emitter == nil {
		return nil, errors.New("keyops: a store and an audit emitter are required")
	}
	return &Admin{store: store, audit: emitter}, nil
}

func summarize(fp *FieldPolicy) string {
	if fp == nil {
		return "absent"
	}
	sum := sha256.Sum256([]byte(fp.Secret))
	ssh := "none"
	if fp.SSHAgent != nil {
		ssh = fmt.Sprintf("hosts:%d", len(fp.SSHAgent.HostKeys))
	}
	return fmt.Sprintf("ops=%s algs=%s agent_decrypt=%t ssh_agent=%s secret=%s",
		strings.Join(fp.Operations, ","), strings.Join(fp.Algorithms, ","), fp.AgentDecrypt, ssh, hex.EncodeToString(sum[:4]))
}

func (a *Admin) record(ctx context.Context, c Caller, change, conn, field string, before, after *FieldPolicy, outcome audit.Outcome, reason, proof string) error {
	extra := map[string]any{
		"change": change, "connection": conn, "field": field, "caller_kind": c.Kind,
		"before": summarize(before), "after": summarize(after),
	}
	if reason != "" {
		extra["reason"] = reason
	}
	if proof != "" {
		extra["presence_digest"] = proof
	}
	return a.audit.Emit(ctx, audit.Event{Action: audit.ActionKeyPolicyChange, Outcome: outcome, Extra: extra})
}

func union(base, add []string) []string {
	out := slices.Clone(base)
	for _, v := range add {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

func normalizeAlgs(algs []string) ([]string, error) {
	out := make([]string, 0, len(algs))
	for _, a := range algs {
		n, ok := NormalizeAlgorithm(a)
		if !ok {
			return nil, fmt.Errorf("%w: unknown algorithm %q", ErrInvalid, a)
		}
		out = append(out, n)
	}
	return out, nil
}

func lookupField(doc Document, conn, field string) *FieldPolicy {
	if fp, ok := doc[conn][field]; ok {
		return &fp
	}
	return nil
}

// Allow adds or widens an entry. Agent and host callers are refused.
func (a *Admin) Allow(ctx context.Context, c Caller, ch Change) error {
	if ch.Connection == "" || ch.Field == "" {
		return fmt.Errorf("%w: a connection and --field are required", ErrInvalid)
	}
	if c.Constrained {
		_ = a.record(ctx, c, "allow", ch.Connection, ch.Field, nil, nil, audit.OutcomeDenied, "adding or widening the allowlist is human-only", ch.PresenceDigest)
		return deny("changing the allowlist is not available to %s callers", c.Kind)
	}
	algs, err := normalizeAlgs(ch.Algorithms)
	if err != nil {
		return err
	}
	var before, after *FieldPolicy
	prev, err := a.store.update(func(doc Document) error {
		before = lookupField(doc, ch.Connection, ch.Field)
		fp := FieldPolicy{}
		if before != nil {
			fp = *before
			fp.Operations, fp.Algorithms = slices.Clone(fp.Operations), slices.Clone(fp.Algorithms)
		}
		if ch.Secret != "" {
			fp.Secret = ch.Secret
		}
		fp.Operations = union(fp.Operations, ch.Operations)
		fp.Algorithms = union(fp.Algorithms, algs)
		fp.AgentDecrypt = fp.AgentDecrypt || ch.AgentDecrypt
		if ch.SSHAgent || len(ch.HostKeys) > 0 {
			hosts := []string{}
			if fp.SSHAgent != nil {
				hosts = fp.SSHAgent.HostKeys
			}
			fp.SSHAgent = &SSHPolicy{HostKeys: union(hosts, ch.HostKeys)}
		}
		fp, err := validateField(fp)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if doc[ch.Connection] == nil {
			doc[ch.Connection] = map[string]FieldPolicy{}
		}
		doc[ch.Connection][ch.Field] = fp
		after = &fp
		return nil
	})
	if err != nil {
		return err
	}
	if aerr := a.record(ctx, c, "allow", ch.Connection, ch.Field, before, after, audit.OutcomeOK, "", ch.PresenceDigest); aerr != nil {
		a.store.restore(prev)
		return fmt.Errorf("%w: audit log is not writable", ErrUnavailable)
	}
	return nil
}

// Revoke narrows or removes an entry. With no operations, algorithms or
// flags it removes the field, or every field of the connection when no field
// is given. Any caller may revoke.
func (a *Admin) Revoke(ctx context.Context, c Caller, ch Change) error {
	if ch.Connection == "" {
		return fmt.Errorf("%w: a connection is required", ErrInvalid)
	}
	if len(ch.HostKeys) > 0 || ch.Secret != "" {
		return fmt.Errorf("%w: revoke cannot add host keys or change the secret", ErrInvalid)
	}
	narrowing := len(ch.Operations) > 0 || len(ch.Algorithms) > 0 || ch.AgentDecrypt || ch.SSHAgent
	if narrowing && ch.Field == "" {
		return fmt.Errorf("%w: pass --field to narrow an entry", ErrInvalid)
	}
	algs, err := normalizeAlgs(ch.Algorithms)
	if err != nil {
		return err
	}
	type edit struct {
		field         string
		before, after *FieldPolicy
	}
	var edits []edit
	prev, err := a.store.update(func(doc Document) error {
		fields, ok := doc[ch.Connection]
		if !ok || (ch.Field != "" && lookupField(doc, ch.Connection, ch.Field) == nil) {
			return fmt.Errorf("%w: nothing is configured for %q", ErrNotFound, ch.Connection)
		}
		for name, fp := range fields {
			if ch.Field != "" && name != ch.Field {
				continue
			}
			before := fp
			if !narrowing {
				delete(fields, name)
				edits = append(edits, edit{name, &before, nil})
				continue
			}
			fp.Operations = slices.DeleteFunc(slices.Clone(fp.Operations), func(o string) bool { return slices.Contains(ch.Operations, o) })
			fp.Algorithms = slices.DeleteFunc(slices.Clone(fp.Algorithms), func(g string) bool { return slices.Contains(algs, g) })
			if ch.AgentDecrypt {
				fp.AgentDecrypt = false
			}
			if ch.SSHAgent {
				fp.SSHAgent = nil
			}
			fields[name] = fp
			edits = append(edits, edit{name, &before, &fp})
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].field < edits[j].field })
	for _, e := range edits {
		if aerr := a.record(ctx, c, "revoke", ch.Connection, e.field, e.before, e.after, audit.OutcomeOK, "", ""); aerr != nil {
			a.store.restore(prev)
			return fmt.Errorf("%w: audit log is not writable", ErrUnavailable)
		}
	}
	return nil
}

type listEntry struct {
	BackendPath  string     `json:"backend_path,omitempty"`
	Operations   []string   `json:"operations"`
	Algorithms   []string   `json:"algorithms"`
	AgentDecrypt bool       `json:"agent_decrypt,omitempty"`
	SSHAgent     *SSHPolicy `json:"ssh_agent,omitempty"`
}

// List returns the allowlist as JSON. Agent and host callers do not see the
// backend path of a key.
func (a *Admin) List(c Caller, connection string) ([]byte, error) {
	doc, err := a.store.Load()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	out := map[string]map[string]listEntry{}
	for conn, fields := range doc {
		if connection != "" && conn != connection {
			continue
		}
		out[conn] = map[string]listEntry{}
		for name, fp := range fields {
			e := listEntry{Operations: fp.Operations, Algorithms: fp.Algorithms, AgentDecrypt: fp.AgentDecrypt, SSHAgent: fp.SSHAgent}
			if !c.Constrained {
				e.BackendPath = fp.Secret
			}
			out[conn][name] = e
		}
	}
	return json.MarshalIndent(out, "", "  ")
}
