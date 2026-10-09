package redactor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ScanPolicy selects what happens to files that contain a secret.
type ScanPolicy int

const (
	// ScanReport leaves files untouched and only reports them.
	ScanReport ScanPolicy = iota
	// ScanRedact rewrites files in place with matches replaced by Marker.
	ScanRedact
)

// maxScanSize bounds the work spent on one file; larger changed files are
// reported as unscanned rather than silently skipped.
const maxScanSize = 512 << 20

// ErrTreeTooLarge is returned by TakeSnapshot when the tree has more files
// than can be tracked cheaply.
var ErrTreeTooLarge = errors.New("redactor: too many files to snapshot")

const maxSnapshotFiles = 250000

type stamp struct {
	size    int64
	modTime int64
	ctime   int64
}

// Snapshot records file metadata so files written afterwards can be found
// even when the writer restores timestamps (ctime cannot be set by the
// owner on Linux and macOS).
type Snapshot struct {
	root  string
	files map[string]stamp
}

// Finding describes one path that held a secret value or encoding.
type Finding struct {
	Path string
	// Name is set when the file name itself encodes a secret.
	Name     bool
	Redacted bool
	// Unscanned is set for changed files too large to scan.
	Unscanned bool
}

func walkFiles(root string, visit func(path string, info fs.FileInfo) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return visit(path, info)
	})
}

// TakeSnapshot records the current state of every regular file under root.
func TakeSnapshot(root string) (*Snapshot, error) {
	s := &Snapshot{root: root, files: map[string]stamp{}}
	err := walkFiles(root, func(path string, info fs.FileInfo) error {
		if len(s.files) >= maxSnapshotFiles {
			return ErrTreeTooLarge
		}
		s.files[path] = stampOf(info)
		return nil
	})
	return s, err
}

func stampOf(info fs.FileInfo) stamp {
	return stamp{size: info.Size(), modTime: info.ModTime().UnixNano(), ctime: changeTime(info)}
}

// ScanChanged inspects files under the snapshot root that are new or changed
// since the snapshot and applies policy to those that contain a secret value
// or encoding.
func (m *Matcher) ScanChanged(before *Snapshot, policy ScanPolicy) ([]Finding, error) {
	if m.Empty() {
		return nil, nil
	}
	var findings []Finding
	err := walkFiles(before.root, func(path string, info fs.FileInfo) error {
		if old, ok := before.files[path]; ok && old == stampOf(info) {
			return nil
		}
		f := Finding{Path: path}
		if m.Contains([]byte(filepath.Base(path))) {
			f.Name = true
		}
		if info.Size() > maxScanSize {
			f.Unscanned = true
		} else {
			hit, err := m.scanFile(path, policy)
			if err != nil {
				return fmt.Errorf("scan %s: %w", path, err)
			}
			f.Redacted = hit && policy == ScanRedact
			if !hit && !f.Name {
				return nil
			}
		}
		findings = append(findings, f)
		return nil
	})
	return findings, err
}

func (m *Matcher) scanFile(path string, policy ScanPolicy) (bool, error) {
	in, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer func() { _ = in.Close() }()
	probe := m.NewWriter(io.Discard)
	if _, err := io.Copy(probe, in); err != nil {
		return false, err
	}
	if err := probe.Close(); err != nil {
		return false, err
	}
	if probe.Matches() == 0 || policy != ScanRedact {
		return probe.Matches() > 0, nil
	}
	return true, m.rewrite(path, in)
}

func (m *Matcher) rewrite(path string, in *os.File) error {
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if _, err := in.Seek(0, io.SeekStart); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".redact-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	w := m.NewWriter(tmp)
	_, copyErr := io.Copy(w, in)
	closeErr := errors.Join(w.Close(), tmp.Chmod(info.Mode().Perm()), tmp.Close())
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
