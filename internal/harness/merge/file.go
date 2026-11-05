package merge

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pmezard/go-difflib/difflib"
)

// BackupSuffix is appended to a file's name for the copy saved before a change.
const BackupSuffix = ".keylatch.bak"

// Change is the outcome of editing one file.
type Change struct {
	Path string
	// Changed is true when the file was (or, in a dry run, would be) written.
	Changed bool
	// Created is true when the file did not exist.
	Created bool
	// Diff is a unified diff of the change, set when Changed.
	Diff string
	// Backup is the copy of the previous content, set when a file that existed
	// was rewritten.
	Backup string
}

// Options controls Apply.
type Options struct {
	// DryRun computes the change and writes nothing.
	DryRun bool
	// Perm is the mode of a file Apply creates; 0o600 when zero.
	Perm os.FileMode
}

// Apply reads path (a missing file is empty), lets edit produce the new
// content and, when it differs, saves the old content as path.keylatch.bak and
// writes the new one atomically. A symbolic link is followed so a dotfile
// manager's link stays a link.
func Apply(path string, opts Options, edit func(old []byte) ([]byte, error)) (Change, error) {
	change := Change{Path: path}
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	old, err := os.ReadFile(target) //nolint:gosec // G304: the harness's own configuration file
	exists := err == nil
	if err != nil && !os.IsNotExist(err) {
		return change, fmt.Errorf("read %s: %w", path, err)
	}
	updated, err := edit(old)
	if err != nil {
		return change, fmt.Errorf("%s: %w", path, err)
	}
	if bytes.Equal(old, updated) {
		return change, nil
	}
	change.Changed, change.Created = true, !exists
	change.Diff = unifiedDiff(path, old, updated)
	if opts.DryRun {
		return change, nil
	}
	perm := opts.Perm
	if perm == 0 {
		perm = 0o600
	}
	if exists {
		if info, err := os.Stat(target); err == nil {
			perm = info.Mode().Perm()
		}
		change.Backup = target + BackupSuffix
		if err := os.WriteFile(change.Backup, old, 0o600); err != nil {
			return change, fmt.Errorf("write backup %s: %w", change.Backup, err)
		}
	}
	return change, writeAtomic(target, updated, perm)
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".keylatch-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil && !isWindowsChmod(err) {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// isWindowsChmod reports whether err is the harmless refusal to set Unix mode
// bits on a platform that has none.
func isWindowsChmod(err error) bool { return err != nil && filepath.Separator == '\\' }

func unifiedDiff(path string, before, after []byte) string {
	d, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(before)),
		B:        difflib.SplitLines(string(after)),
		FromFile: path,
		ToFile:   path + " (after install)",
		Context:  3,
	})
	if err != nil {
		return fmt.Sprintf("cannot render the diff for %s: %v\n", path, err)
	}
	return d
}
