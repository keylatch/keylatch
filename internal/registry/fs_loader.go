package registry

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// LoadAll implements Loader. It walks Dir looking for *.yaml files, validates
// each against the provider template schema, and returns LoadedTemplates.
//
// If Dir does not exist the method returns (nil, nil) — no error.
// If RequireSig is true and a *.yaml.sig file is absent alongside the template,
// the template is skipped with a warning.
//
// Built-in templates in the fs_loader are shipped with the binary and do not
// require cosign verification. Only community bundles (LoadBundle) are subject
// to FIND-008 signature verification.
func (f *FSLoader) LoadAll(_ context.Context) ([]LoadedTemplate, error) {
	info, err := os.Stat(f.Dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fs_loader: stat %q: %w", f.Dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("fs_loader: %q is not a directory", f.Dir)
	}

	var results []LoadedTemplate

	err = filepath.WalkDir(f.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".yaml") && !strings.HasSuffix(p, ".yml") {
			return nil
		}

		if f.RequireSig {
			sigPath := p + ".sig"
			if _, serr := os.Stat(sigPath); os.IsNotExist(serr) {
				// Community bundles require a .sig file (FIND-008). Skip unsigned templates.
				slog.Warn("registry: skipping unsigned community template", "path", p)
				return nil
			}
		}

		data, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("read %q: %w", p, err)
		}

		if err := validateTemplateBytes(data); err != nil {
			return fmt.Errorf("template %q: %w", filepath.Base(p), err)
		}

		tmpl, err := parseTemplate(data)
		if err != nil {
			return fmt.Errorf("parse %q: %w", p, err)
		}

		src := SourceLocal
		if f.Tier == TierCommunity {
			src = SourceCommunity
		}

		results = append(results, LoadedTemplate{
			Template: tmpl,
			Source:   src,
			Tier:     f.Tier,
			Path:     p,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	return results, nil
}
