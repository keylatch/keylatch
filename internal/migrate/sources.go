package migrate

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Runner runs an external tool and returns its standard output. It never
// returns the tool's standard error, which can echo a secret.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Env is everything the scanners and readers touch outside this package.
type Env struct {
	Home     string
	GOOS     string
	Run      Runner
	ReadFile func(string) ([]byte, error)
	Glob     func(string) ([]string, error)
}

func (e Env) withDefaults() Env {
	if e.ReadFile == nil {
		e.ReadFile = os.ReadFile
	}
	if e.Glob == nil {
		e.Glob = filepath.Glob
	}
	return e
}

func (e Env) expand(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(e.Home, strings.TrimPrefix(p, "~"))
	}
	return p
}

// Inventory scans every source of the map and returns a plan of names and
// references. It reads no value: env files are parsed for their keys, and the
// output of secret-tool is filtered before anything is kept.
func Inventory(ctx context.Context, m Map, env Env) (Plan, error) {
	env = env.withDefaults()
	plan := Plan{Version: 1, Items: []PlanItem{}}
	seen := map[string]bool{}
	add := func(spec SourceSpec, name, ref string) {
		col, path := itemPath(m, spec.Namespace, name)
		if seen[path] {
			return
		}
		seen[path] = true
		plan.Items = append(plan.Items, PlanItem{Name: name, Source: spec.Type, Ref: ref, Namespace: spec.Namespace, Collection: col, Path: path})
	}
	for _, spec := range m.Sources {
		var err error
		switch spec.Type {
		case SourceEnvFile:
			err = scanEnvFiles(spec, env, add)
		case SourceSecretService:
			err = scanSecretService(ctx, spec, env, add)
		case SourceKeychain:
			for _, a := range spec.Accounts {
				add(spec, a, "kc:"+spec.Service+":"+a)
			}
		case SourceGitHubCLI:
			err = scanGitHub(spec, env, add)
		case SourcePasswordManager:
			for _, it := range spec.Items {
				add(spec, it, "pm:"+spec.Manager+":"+it)
			}
		}
		if err != nil {
			return Plan{}, fmt.Errorf("migrate inventory: %s: %w", spec.Type, err)
		}
	}
	sort.SliceStable(plan.Items, func(i, j int) bool { return plan.Items[i].Path < plan.Items[j].Path })
	return plan, nil
}

type adder func(spec SourceSpec, name, ref string)

func scanEnvFiles(spec SourceSpec, env Env, add adder) error {
	files, err := env.Glob(env.expand(spec.Glob))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		data, err := env.ReadFile(f)
		if err != nil {
			continue
		}
		for _, kv := range parseEnv(data) {
			add(spec, kv.key, "env:"+f+"#"+kv.key)
		}
	}
	return nil
}

type envPair struct{ key, value string }

// parseEnv reads KEY=value lines. Inventory keeps only the keys.
func parseEnv(data []byte) []envPair {
	var out []envPair
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.ContainsAny(k, " \t") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out = append(out, envPair{k, v})
	}
	return out
}

func scanSecretService(ctx context.Context, spec SourceSpec, env Env, add adder) error {
	if env.Run == nil {
		return errors.New("no command runner")
	}
	out, err := env.Run(ctx, "secret-tool", "search", "--all", "service", spec.Service)
	if err != nil {
		return fmt.Errorf("secret-tool: %w", err)
	}
	var label, account string
	flush := func() {
		name := account
		if name == "" {
			name = label
		}
		if name != "" {
			add(spec, name, "ss:"+spec.Service+":"+name)
		}
		label, account = "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "["):
			flush()
		case strings.HasPrefix(line, "label = "):
			label = strings.TrimPrefix(line, "label = ")
		case strings.HasPrefix(line, "attribute.account = "):
			account = strings.TrimPrefix(line, "attribute.account = ")
		}
	}
	flush()
	return nil
}

func scanGitHub(spec SourceSpec, env Env, add adder) error {
	data, err := env.ReadFile(filepath.Join(env.Home, ".config", "gh", "hosts.yml"))
	if err != nil {
		return nil
	}
	var hosts map[string]struct{}
	if err := yaml.Unmarshal(data, &hosts); err != nil {
		return fmt.Errorf("gh hosts: %w", err)
	}
	names := make([]string, 0, len(hosts))
	for h := range hosts {
		if len(spec.Hosts) == 0 || contains(spec.Hosts, h) {
			names = append(names, h)
		}
	}
	sort.Strings(names)
	for _, h := range names {
		add(spec, "gh-"+h, "gh:"+h)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ReadValue fetches the value an item's reference points at. The caller wipes it.
func ReadValue(ctx context.Context, it PlanItem, env Env) ([]byte, error) {
	env = env.withDefaults()
	kind, rest, _ := strings.Cut(it.Ref, ":")
	run := func(name string, args ...string) ([]byte, error) {
		if env.Run == nil {
			return nil, errors.New("no command runner")
		}
		out, err := env.Run(ctx, name, args...)
		if err != nil {
			return nil, fmt.Errorf("%s failed", name)
		}
		return bytes.TrimRight(out, "\r\n"), nil
	}
	switch kind {
	case "env":
		file, key, _ := strings.Cut(rest, "#")
		data, err := env.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", file, err)
		}
		for _, kv := range parseEnv(data) {
			if kv.key == key {
				return []byte(kv.value), nil
			}
		}
		return nil, fmt.Errorf("%s no longer defines %s", file, key)
	case "ss":
		svc, acct, _ := strings.Cut(rest, ":")
		return run("secret-tool", "lookup", "service", svc, "account", acct)
	case "kc":
		svc, acct, _ := strings.Cut(rest, ":")
		return run("security", "find-generic-password", "-s", svc, "-a", acct, "-w")
	case "gh":
		return run("gh", "auth", "token", "--hostname", rest)
	case "pm":
		mgr, item, _ := strings.Cut(rest, ":")
		if mgr == "bw" {
			return run("bw", "get", "password", item)
		}
		return run("op", "item", "get", item, "--fields", "label=password", "--reveal")
	}
	return nil, fmt.Errorf("unknown reference %q", it.Ref)
}
