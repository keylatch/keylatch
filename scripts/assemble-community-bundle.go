//go:build ignore

// assemble-community-bundle assembles all provider YAML templates in a directory
// into a single community.json bundle for distribution.
//
// Usage: go run ./scripts/assemble-community-bundle.go \
//
//	--templates-dir templates/providers \
//	--output dist/provider-bundles/community.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func main() {
	templatesDir := flag.String("templates-dir", "templates/providers", "directory of provider YAML templates")
	output := flag.String("output", "dist/provider-bundles/community.json", "output bundle path")
	flag.Parse()

	entries, err := os.ReadDir(*templatesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read templates dir: %v\n", err)
		os.Exit(1)
	}

	var templates []any
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(*templatesDir, e.Name()))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", e.Name(), err)
			os.Exit(1)
		}
		var t any
		if err := yaml.Unmarshal(data, &t); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", e.Name(), err)
			os.Exit(1)
		}
		templates = append(templates, t)
	}

	if len(templates) == 0 {
		fmt.Fprintf(os.Stderr, "error: no .yaml templates found in %s\n", *templatesDir)
		os.Exit(1)
	}

	// parseBundleData in internal/registry/verify.go expects a bare JSON array,
	// not a wrapper object — marshal templates directly.
	out, err := json.MarshalIndent(templates, "", " ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal bundle: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*output, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write bundle: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Assembled %d templates → %s\n", len(templates), *output)
}
