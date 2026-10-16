// Package migrate inventories the secrets scattered over a machine, imports
// them into a Keylatch backend and proves afterwards, on any host, that every
// item still holds the value it had. An inventory and a plan carry names,
// sources and target namespaces only. A manifest carries a keyed hash per item
// that only the recovery passphrase can recompute.
package migrate

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source kinds.
const (
	SourceEnvFile         = "env-file"
	SourceSecretService   = "secret-service"
	SourceKeychain        = "keychain"
	SourceGitHubCLI       = "gh"
	SourcePasswordManager = "password-manager"
)

// Map says where to look for secrets and which namespace each source lands in.
type Map struct {
	Version int `yaml:"version" json:"version"`
	// Collections maps a namespace to the backend collection it is stored under.
	Collections map[string]string `yaml:"collections,omitempty" json:"collections,omitempty"`
	Sources     []SourceSpec      `yaml:"sources" json:"sources"`
}

// SourceSpec is one place to scan.
type SourceSpec struct {
	Type      string `yaml:"type" json:"type"`
	Namespace string `yaml:"namespace" json:"namespace"`
	// Glob selects env files (env-file).
	Glob string `yaml:"glob,omitempty" json:"glob,omitempty"`
	// Service is the secret-service or keychain service attribute.
	Service string `yaml:"service,omitempty" json:"service,omitempty"`
	// Accounts names the keychain accounts to include; the macOS keychain
	// cannot be enumerated without reading it.
	Accounts []string `yaml:"accounts,omitempty" json:"accounts,omitempty"`
	// Manager is bw or op (password-manager); Items are the item names.
	Manager string   `yaml:"manager,omitempty" json:"manager,omitempty"`
	Items   []string `yaml:"items,omitempty" json:"items,omitempty"`
	// Hosts limits gh to these hosts; empty means every host gh is logged in to.
	Hosts []string `yaml:"hosts,omitempty" json:"hosts,omitempty"`
}

// Plan is an inventory: what would be imported and where it would go.
type Plan struct {
	Version int        `json:"version"`
	Items   []PlanItem `json:"items"`
}

// PlanItem is one secret. Ref says how to read it from its source and never
// contains the value.
type PlanItem struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	Ref        string `json:"ref"`
	Namespace  string `json:"namespace"`
	Collection string `json:"collection,omitempty"`
	Path       string `json:"path"`
}

var (
	nsPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	namePattern = regexp.MustCompile(`[^a-z0-9._-]+`)
)

// ParseMap decodes and validates a map document, refusing unknown keys.
func ParseMap(data []byte) (Map, error) {
	var m Map
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return Map{}, fmt.Errorf("migrate map: %w", err)
	}
	return m, m.Validate()
}

// Validate checks the map's shape.
func (m Map) Validate() error {
	if m.Version != 1 {
		return errors.New("migrate map: version must be 1")
	}
	if len(m.Sources) == 0 {
		return errors.New("migrate map: sources must not be empty")
	}
	for ns := range m.Collections {
		if !nsPattern.MatchString(ns) {
			return fmt.Errorf("migrate map: collections.%s: not a namespace", ns)
		}
	}
	for i, s := range m.Sources {
		at := fmt.Sprintf("migrate map: sources[%d]", i)
		if !nsPattern.MatchString(s.Namespace) {
			return fmt.Errorf("%s.namespace: %q is not a lower-case namespace", at, s.Namespace)
		}
		switch s.Type {
		case SourceEnvFile:
			if s.Glob == "" {
				return fmt.Errorf("%s.glob: required for env-file", at)
			}
		case SourceSecretService:
			if s.Service == "" {
				return fmt.Errorf("%s.service: required for secret-service", at)
			}
		case SourceKeychain:
			if s.Service == "" || len(s.Accounts) == 0 {
				return fmt.Errorf("%s: keychain needs service and accounts", at)
			}
		case SourceGitHubCLI:
		case SourcePasswordManager:
			if (s.Manager != "bw" && s.Manager != "op") || len(s.Items) == 0 {
				return fmt.Errorf("%s: password-manager needs manager bw|op and items", at)
			}
		default:
			return fmt.Errorf("%s.type: unknown source %q", at, s.Type)
		}
	}
	return nil
}

// ParsePlan decodes and validates a plan document.
func ParsePlan(data []byte) (Plan, error) {
	var p Plan
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return Plan{}, fmt.Errorf("migrate plan: %w", err)
	}
	if p.Version != 1 {
		return Plan{}, errors.New("migrate plan: version must be 1")
	}
	seen := map[string]bool{}
	for i, it := range p.Items {
		if it.Name == "" || it.Path == "" || it.Ref == "" || it.Source == "" {
			return Plan{}, fmt.Errorf("migrate plan: items[%d]: name, source, ref and path are required", i)
		}
		if seen[it.Path] {
			return Plan{}, fmt.Errorf("migrate plan: items[%d]: path %q appears twice", i, it.Path)
		}
		seen[it.Path] = true
	}
	return p, nil
}

func itemPath(m Map, ns, name string) (collection, path string) {
	collection = m.Collections[ns]
	if collection == "" {
		collection = ns
	}
	return collection, collection + "/" + SafeName(name)
}

// SafeName lower-cases name and replaces what a path cannot hold.
func SafeName(name string) string {
	n := strings.Trim(namePattern.ReplaceAllString(strings.ToLower(name), "-"), "-.")
	if n == "" {
		return "item"
	}
	return n
}
