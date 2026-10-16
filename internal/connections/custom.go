package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/registry"
)

// CallerKind classifies who is changing a binding.
type CallerKind string

const (
	CallerHuman CallerKind = "human"
	CallerAgent CallerKind = "agent"
)

// Binding change kinds.
const (
	ChangeCreated   = "created"
	ChangeWidened   = "widened"
	ChangeNarrowed  = "narrowed"
	ChangeUnchanged = "unchanged"
)

// ErrBindingHumanOnly is returned when a non-human caller creates or widens a binding.
var ErrBindingHumanOnly = errors.New("connections: creating or widening a binding is human-only")

var customNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// BindingChange describes how a save altered a connection's binding.
type BindingChange struct {
	Kind        string
	HostsBefore []string
	HostsAfter  []string
}

// CustomOptions carries the parameters of SaveCustom.
type CustomOptions struct {
	Namespace string
	// Fields are the secret field values (or provider references); required on create.
	Fields  map[string][]byte
	Binding registry.CustomBinding
	Caller  CallerKind
	// Approve, when set, is asked about a creation or a widening after the
	// change is known and before anything is written. An error from it stops
	// the save.
	Approve func(BindingChange) error
}

func customPath(ns, name, leaf string) string {
	return fmt.Sprintf("%s/custom/%s/%s", ns, name, leaf)
}

// SaveCustom creates a custom connection or replaces its binding. Creating or
// widening is refused for non-human callers; the returned change still
// describes the attempt so it can be audited.
func SaveCustom(ctx context.Context, name string, opts CustomOptions, st Store) (BindingChange, error) {
	if !customNamePattern.MatchString(name) {
		return BindingChange{}, fmt.Errorf("connections: invalid custom connection name %q", name)
	}
	ns := opts.Namespace
	if ns == "" {
		ns = "default"
	}
	old, existing, err := loadCustom(ctx, st, ns, name)
	if err != nil {
		return BindingChange{}, err
	}

	var fieldNames []string
	switch {
	case existing && len(opts.Fields) > 0:
		return BindingChange{}, ErrConnectionExists
	case existing:
		if fieldNames, _, err = CustomFields(ctx, st, ns, name); err != nil {
			return BindingChange{}, err
		}
	default:
		for f, v := range opts.Fields {
			if len(v) == 0 {
				return BindingChange{}, fmt.Errorf("connections: field %q is empty", f)
			}
			fieldNames = append(fieldNames, f)
		}
		if len(fieldNames) == 0 {
			return BindingChange{}, errors.New("connections: a custom connection needs a secret field")
		}
		sort.Strings(fieldNames)
	}
	if err := opts.Binding.Validate(name, fieldNames); err != nil {
		return BindingChange{}, err
	}

	change := BindingChange{HostsAfter: sorted(opts.Binding.Hosts)}
	switch {
	case !existing:
		change.Kind = ChangeCreated
	case old.WidenedBy(opts.Binding):
		change.Kind, change.HostsBefore = ChangeWidened, sorted(old.Hosts)
	case !opts.Binding.WidenedBy(old):
		change.Kind, change.HostsBefore = ChangeUnchanged, sorted(old.Hosts)
	default:
		change.Kind, change.HostsBefore = ChangeNarrowed, sorted(old.Hosts)
	}
	if (change.Kind == ChangeCreated || change.Kind == ChangeWidened) && opts.Caller != CallerHuman {
		return change, ErrBindingHumanOnly
	}
	if (change.Kind == ChangeCreated || change.Kind == ChangeWidened) && opts.Approve != nil {
		if err := opts.Approve(change); err != nil {
			return change, err
		}
	}

	if !existing {
		if err := writeCustomSecrets(ctx, st, ns, name, opts.Fields); err != nil {
			return change, err
		}
	}
	data, err := json.Marshal(opts.Binding)
	if err != nil {
		return change, fmt.Errorf("connections: encode binding: %w", err)
	}
	if err := st.Set(ctx, customPath(ns, name, "binding"), data, backend.Meta{Path: customPath(ns, name, "binding"), Backend: "vault", Version: 1}); err != nil {
		return change, fmt.Errorf("connections: write binding: %w", err)
	}
	if existing {
		return change, nil
	}
	now := time.Now().UTC()
	conn := &Connection{Provider: name, Account: "default", Namespace: ns, CreatedAt: now, UpdatedAt: now, Fields: fieldNames, Status: "untested"}
	meta, err := marshalConnection(conn)
	if err != nil {
		return change, fmt.Errorf("connections: marshal connection metadata: %w", err)
	}
	if err := st.Set(ctx, customPath(ns, name, "meta"), meta, backend.Meta{Path: customPath(ns, name, "meta"), Backend: "vault", Version: 1}); err != nil {
		return change, fmt.Errorf("connections: write connection metadata: %w", err)
	}
	return change, nil
}

// CustomFields returns the secret field names of a custom connection; ok is
// false when the connection does not exist.
func CustomFields(ctx context.Context, st Store, ns, name string) (fields []string, ok bool, err error) {
	if ns == "" {
		ns = "default"
	}
	data, _, err := st.Get(ctx, customPath(ns, name, "meta"))
	if errors.Is(err, backend.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("connections: read metadata: %w", err)
	}
	c, err := unmarshalConnection(data)
	if err != nil {
		return nil, false, fmt.Errorf("connections: decode metadata: %w", err)
	}
	return c.Fields, true, nil
}

func writeCustomSecrets(ctx context.Context, st Store, ns, name string, fields map[string][]byte) error {
	for f, v := range fields {
		p := customPath(ns, name, f)
		err := st.Set(ctx, p, v, backend.Meta{Path: p, Backend: "vault", Version: 1})
		zeroBytes(v)
		if err != nil {
			return fmt.Errorf("connections: write field %q: %w", f, err)
		}
	}
	return nil
}

func loadCustom(ctx context.Context, st Store, ns, name string) (registry.CustomBinding, bool, error) {
	data, _, err := st.Get(ctx, customPath(ns, name, "binding"))
	if errors.Is(err, backend.ErrNotFound) {
		return registry.CustomBinding{}, false, nil
	}
	if err != nil {
		return registry.CustomBinding{}, false, fmt.Errorf("connections: read binding: %w", err)
	}
	var b registry.CustomBinding
	if err := json.Unmarshal(data, &b); err != nil {
		return registry.CustomBinding{}, false, fmt.Errorf("connections: decode binding: %w", err)
	}
	return b, true, nil
}

// CustomBindingFor returns the stored binding of a custom connection as the
// same contract templates expose; registry.ErrNoBinding when it has none.
func CustomBindingFor(ctx context.Context, st Store, ns, name string) (registry.Binding, error) {
	if ns == "" {
		ns = "default"
	}
	b, ok, err := loadCustom(ctx, st, ns, name)
	if err != nil {
		return registry.Binding{}, err
	}
	if !ok {
		return registry.Binding{}, fmt.Errorf("custom connection %q: %w", name, registry.ErrNoBinding)
	}
	return b.Binding(name), nil
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}
