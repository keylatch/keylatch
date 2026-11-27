package connpolicy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/keylatch/keylatch/internal/callerkind"
)

// yamlPolicy is the one-file form of policy: defaults every connection starts
// from, the connections, and argv pins that name the connections they apply to.
// ParseYAML compiles it into one Document per connection.
type yamlPolicy struct {
	SchemaVersion int                       `yaml:"schema_version"`
	Defaults      yamlDefaults              `yaml:"defaults"`
	Connections   map[string]yamlConnection `yaml:"connections"`
	Commands      []yamlCommand             `yaml:"commands"`
}

type yamlDefaults struct {
	Caller map[string]yamlCaller `yaml:"caller"`
	Egress *Egress               `yaml:"egress"`
	FS     *FS                   `yaml:"fs"`
}

type yamlConnection struct {
	Description  string                `yaml:"description"`
	Hosts        []string              `yaml:"hosts"`
	Capabilities []string              `yaml:"capabilities"`
	MaxTTL       string                `yaml:"max_ttl"`
	Egress       *Egress               `yaml:"egress"`
	FS           *FS                   `yaml:"fs"`
	Callers      map[string]yamlCaller `yaml:"callers"`
}

type yamlCommand struct {
	Match       []string `yaml:"match"`
	Connections []string `yaml:"connections"`
	Tiers       []string `yaml:"tiers"`
	Approval    string   `yaml:"approval"`
	ExeSHA256   string   `yaml:"exe_sha256"`
}

// yamlCaller is a caller entry: a mapping, or the scalar "deny".
type yamlCaller struct {
	Deny        bool
	Runtimes    []string `yaml:"runtimes"`
	Exe         []string `yaml:"exe"`
	Units       []string `yaml:"units"`
	Tiers       []string `yaml:"tiers"`
	Approval    string   `yaml:"approval"`
	TTL         string   `yaml:"ttl"`
	MaxRequests int      `yaml:"max_requests"`
}

func (c *yamlCaller) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		if n.Value != "deny" {
			return fmt.Errorf("line %d: a caller entry is a mapping or the word deny, not %q", n.Line, n.Value)
		}
		*c = yamlCaller{Deny: true}
		return nil
	}
	type plain yamlCaller
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*c = yamlCaller(p)
	return nil
}

// bindingKeys belong to a connection's definition, not to its policy.
var bindingKeys = []string{"secret", "slots", "routes", "adapter", "upstream", "mint", "fields", "sql", "provider"}

// ParseYAML compiles a policy file into one Document per connection. Caller
// entries a connection does not list come from the defaults; command pins are
// added to the connections they name. A key that defines how a connection
// reaches its secret (secret, slots, adapter, ...) is refused: the policy says
// who may use a connection, `keylatch connect` says what it is.
func ParseYAML(data []byte) (map[string]Document, error) {
	var generic struct {
		Connections map[string]map[string]any `yaml:"connections"`
	}
	if err := yaml.Unmarshal(data, &generic); err == nil {
		for name, conn := range generic.Connections {
			for _, k := range bindingKeys {
				if _, ok := conn[k]; ok {
					return nil, fmt.Errorf("connections.%s.%s: bindings belong to the connection definition (`keylatch connect`), not to the policy", name, k)
				}
			}
		}
	}
	var p yamlPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("policy YAML: %w", err)
	}
	if p.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("policy YAML: schema_version must be %d, got %d", SchemaVersion, p.SchemaVersion)
	}
	if len(p.Connections) == 0 {
		return nil, errors.New("policy YAML: no connections")
	}
	out := make(map[string]Document, len(p.Connections))
	for name, c := range p.Connections {
		d := Document{
			SchemaVersion: SchemaVersion, Description: c.Description, Connection: name, Default: "deny",
			Hosts: c.Hosts, Capabilities: c.Capabilities, MaxTTL: c.MaxTTL, Callers: map[callerkind.Kind]CallerRule{},
		}
		d.Egress, d.FS = pickEgress(c.Egress, p.Defaults.Egress), mergeFS(c.FS, p.Defaults.FS)
		for _, kind := range DocumentKinds {
			entry, ok := c.Callers[string(kind)]
			if !ok {
				entry, ok = p.Defaults.Caller[string(kind)]
			}
			if ok {
				d.Callers[kind] = entry.rule()
			}
		}
		for key := range c.Callers {
			if !slices.Contains(DocumentKinds, callerkind.Kind(key)) {
				return nil, fmt.Errorf("connections.%s.callers.%s is not a caller kind (agent, host, service, human, machine)", name, key)
			}
		}
		for _, cmd := range p.Commands {
			if slices.Contains(cmd.Connections, name) {
				d.Commands = append(d.Commands, CommandRule{Match: cmd.Match, Tiers: cmd.Tiers, Approval: cmd.Approval, ExeSHA256: cmd.ExeSHA256})
			}
		}
		out[name] = d
	}
	for i, cmd := range p.Commands {
		for _, name := range cmd.Connections {
			if _, ok := out[name]; !ok {
				return nil, fmt.Errorf("commands[%d] names connection %q, which the policy does not define", i, name)
			}
		}
		if len(cmd.Connections) == 0 {
			return nil, fmt.Errorf("commands[%d] names no connections", i)
		}
	}
	// Run every compiled document through the same checks a stored one passes.
	for name, d := range out {
		b, err := Marshal(d)
		if err != nil {
			return nil, err
		}
		if out[name], err = Parse(b); err != nil {
			return nil, fmt.Errorf("connection %q: %w", name, err)
		}
	}
	return out, nil
}

func (c yamlCaller) rule() CallerRule {
	if c.Deny {
		return CallerRule{}
	}
	return CallerRule{
		Allow: true, Runtimes: c.Runtimes, Exe: c.Exe, Units: c.Units, Tiers: c.Tiers,
		Approval: c.Approval, TTL: c.TTL, MaxRequests: c.MaxRequests,
	}
}

func pickEgress(own, def *Egress) *Egress {
	if own != nil {
		return own
	}
	return def
}

// mergeFS takes each list from the connection when it sets one and from the
// defaults otherwise; a connection never loses a default deny.
func mergeFS(own, def *FS) *FS {
	switch {
	case own == nil:
		return def
	case def == nil:
		return own
	}
	m := &FS{Read: own.Read, Write: own.Write, Deny: UnionPaths(own.Deny, def.Deny)}
	if m.Read == nil {
		m.Read = def.Read
	}
	if m.Write == nil {
		m.Write = def.Write
	}
	return m
}
