package connpolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// maxDocumentSize bounds what Parse is asked to read.
const maxDocumentSize = 64 << 10

// Store keeps one document per connection in a directory.
type Store struct {
	Dir string
}

// FileName is the file a connection's document lives in. The fallback uses a
// name no connection can have.
func FileName(connection string) string {
	if connection == Fallback {
		return "_default.json"
	}
	return connection + ".json"
}

func connectionOfFile(name string) (string, bool) {
	base, ok := strings.CutSuffix(name, ".json")
	if !ok {
		return "", false
	}
	if base == "_default" {
		return Fallback, true
	}
	return base, connectionRe.MatchString(base) && base != Fallback
}

// Load returns the connection's document, or nil when it has none.
func (s Store) Load(connection string) (*Document, error) {
	if !connectionRe.MatchString(connection) {
		return nil, fmt.Errorf("connection policy: invalid connection name %q", connection)
	}
	d, err := readDocument(filepath.Join(s.Dir, FileName(connection)), true)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if d.Connection != connection {
		return nil, fmt.Errorf("connection policy %s: names connection %q, not %q", FileName(connection), d.Connection, connection)
	}
	return &d, nil
}

// LoadAll returns every document in the store keyed by connection. A missing
// directory is an empty store.
func (s Store) LoadAll() (map[string]Document, error) {
	return ReadDir(s.Dir, true)
}

// ReadDir validates and returns every document in dir. A file that is not a
// valid document fails the whole read, so a partial set is never used. With
// strict set (the store itself) files must be private and named for their
// connection; a directory being imported may name its files anything, but two
// files for one connection are an error.
func ReadDir(dir string, strict bool) (map[string]Document, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]Document{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("connection policy: read %s: %w", dir, err)
	}
	out := make(map[string]Document, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		d, err := readDocument(filepath.Join(dir, e.Name()), strict)
		if err != nil {
			return nil, err
		}
		if strict {
			if conn, ok := connectionOfFile(e.Name()); !ok || d.Connection != conn {
				return nil, fmt.Errorf("connection policy %s: names connection %q, which belongs in %s", e.Name(), d.Connection, FileName(d.Connection))
			}
		}
		if _, dup := out[d.Connection]; dup {
			return nil, fmt.Errorf("connection policy %s: a second document for connection %q", e.Name(), d.Connection)
		}
		out[d.Connection] = d
	}
	return out, nil
}

func readDocument(path string, checkMode bool) (Document, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Document{}, err
	}
	name := filepath.Base(path)
	if !info.Mode().IsRegular() {
		return Document{}, fmt.Errorf("connection policy %s: not a regular file", name)
	}
	if checkMode && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return Document{}, fmt.Errorf("connection policy %s: unsafe permissions %04o (want 0600)", name, info.Mode().Perm())
	}
	if info.Size() > maxDocumentSize {
		return Document{}, fmt.Errorf("connection policy %s: larger than %d bytes", name, maxDocumentSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, err
	}
	d, err := Parse(data)
	if err != nil {
		return Document{}, fmt.Errorf("connection policy %s: %w", name, err)
	}
	return d, nil
}

// Replace makes docs the whole policy set. The new set is written beside the
// store and swapped in, so a reader sees the old set or the new one and a
// failure leaves the old one in place.
func (s Store) Replace(docs map[string]Document) error {
	parent := filepath.Dir(s.Dir)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("connection policy: %w", err)
	}
	staging, err := os.MkdirTemp(parent, ".policy.d-new-*")
	if err != nil {
		return fmt.Errorf("connection policy: %w", err)
	}
	defer func() { _ = os.RemoveAll(staging) }() // MkdirTemp creates it private (0700)
	for conn, d := range docs {
		b, err := Marshal(d)
		if err != nil {
			return fmt.Errorf("connection policy %s: %w", conn, err)
		}
		if err := writePrivate(filepath.Join(staging, FileName(conn)), b); err != nil {
			return err
		}
	}

	old := s.Dir + ".old"
	if err := os.RemoveAll(old); err != nil {
		return fmt.Errorf("connection policy: %w", err)
	}
	hadOld := true
	if err := os.Rename(s.Dir, old); errors.Is(err, fs.ErrNotExist) {
		hadOld = false
	} else if err != nil {
		return fmt.Errorf("connection policy: %w", err)
	}
	if err := os.Rename(staging, s.Dir); err != nil {
		if hadOld {
			_ = os.Rename(old, s.Dir)
		}
		return fmt.Errorf("connection policy: %w", err)
	}
	_ = os.RemoveAll(old)
	return nil
}

func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("connection policy: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("connection policy: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("connection policy: %w", err)
	}
	return f.Close()
}

// Connections lists the stored connection names in order.
func Connections(docs map[string]Document) []string {
	out := make([]string, 0, len(docs))
	for c := range docs {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
