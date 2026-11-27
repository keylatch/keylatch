// Package sops implements a read-only Backend over a file encrypted with sops
// and age. The daemon decrypts the file in memory with an age identity it
// holds, returns one value at a time, and wipes the rest; the plaintext is
// never written to disk and no sops or age binary is run.
package sops

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

var _ backend.Backend = (*Backend)(nil)

// MaxFileSize bounds the sops file the backend reads.
const MaxFileSize = 8 << 20

// Options configures a Backend.
type Options struct {
	// File is the sops file.
	File string
	// Format is the file format; detected from the name when empty.
	Format Format
	// AgeKey is the text of an age identity file, held by Keylatch.
	AgeKey string
	// AgeKeyFile is a path to an age identity file the daemon can read; used
	// when AgeKey is empty.
	AgeKeyFile string
	// SkipMAC turns off the whole-file MAC check.
	SkipMAC bool
}

// Backend is a read-only view of one sops file.
type Backend struct {
	opts Options
}

// Open validates opts and returns a Backend. The identity is parsed on every
// read, so a bad key surfaces at use time with the file it concerns.
func Open(opts Options) (*Backend, error) {
	switch {
	case opts.File == "":
		return nil, errors.New("sops backend: file is required")
	case opts.AgeKey == "" && opts.AgeKeyFile == "":
		return nil, errors.New("sops backend: an age identity is required (store it with 'keylatch backend login sops' or set age_key_file)")
	}
	if opts.Format == "" {
		opts.Format = DetectFormat(opts.File)
	}
	switch opts.Format {
	case FormatJSON, FormatYAML, FormatDotenv:
	default:
		return nil, fmt.Errorf("sops backend: unknown format %q", opts.Format)
	}
	return &Backend{opts: opts}, nil
}

// Name implements backend.Backend.
func (*Backend) Name() string { return "sops" }

// Capabilities implements backend.Backend.
func (*Backend) Capabilities() []backend.Capability { return []backend.Capability{backend.CapList} }

// ID implements backend.Backend.
func (b *Backend) ID() string { return "sops:" + b.opts.File }

func (b *Backend) read() ([]byte, error) {
	f, err := os.Open(b.opts.File)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", backend.ErrNotFound, b.opts.File)
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck
	return readAll(f, MaxFileSize)
}

func (b *Backend) identities() ([]*Identity, error) {
	text := b.opts.AgeKey
	if text == "" {
		raw, err := os.ReadFile(b.opts.AgeKeyFile)
		if err != nil {
			return nil, fmt.Errorf("sops backend: read the age identity: %w", err)
		}
		defer clear(raw)
		text = string(raw)
	}
	return ParseIdentities(strings.NewReader(text))
}

func (b *Backend) decrypt() (*Values, error) {
	data, err := b.read()
	if err != nil {
		return nil, err
	}
	ids, err := b.identities()
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, id := range ids {
			id.Clear()
		}
	}()
	return Decrypt(b.opts.Format, data, ids, DecryptOptions{SkipMAC: b.opts.SkipMAC})
}

// Get returns the value at path ("a/b/c" for nested files, KEY for dotenv).
func (b *Backend) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	vals, err := b.decrypt()
	if err != nil {
		return nil, backend.Meta{}, err
	}
	defer vals.Clear()
	v, ok := vals.Lookup(path)
	if !ok {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
	}
	return v, backend.Meta{Path: path, Backend: "sops", Version: 1}, nil
}

// List returns the value paths in the file. Key names are plaintext in a sops
// file, so nothing is decrypted.
func (b *Backend) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	data, err := b.read()
	if err != nil {
		return nil, err
	}
	paths, err := Paths(b.opts.Format, data)
	if err != nil {
		return nil, err
	}
	var out []backend.Entry
	for _, p := range paths {
		if strings.HasPrefix(p, prefix) {
			out = append(out, backend.Entry{Meta: backend.Meta{Path: p, Backend: "sops", Version: 1}, Exists: true})
		}
	}
	return out, nil
}

// Paths lists the leaf paths of a sops file without decrypting it.
func Paths(format Format, data []byte) ([]string, error) {
	root, _, err := parse(format, data)
	if err != nil {
		return nil, err
	}
	var out []string
	collect(root, "", &out)
	sort.Strings(out)
	return slices.Compact(out), nil
}

func collect(n *node, prefix string, out *[]string) {
	switch n.kind {
	case mapNode:
		for i, k := range n.kids {
			if k.kind == commentNode {
				continue
			}
			collect(k, join(prefix, n.keys[i]), out)
		}
	case listNode:
		idx := 0
		for _, k := range n.kids {
			if k.kind == commentNode || isCommentValue(k.text) {
				continue
			}
			collect(k, join(prefix, strconv.Itoa(idx)), out)
			idx++
		}
	default:
		*out = append(*out, prefix)
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}

var errReadOnly = fmt.Errorf("sops backend is read-only: edit the file with sops; %w", backend.ErrNotSupported)

// Set is refused.
func (*Backend) Set(context.Context, string, []byte, backend.Meta) error { return errReadOnly }

// Delete is refused.
func (*Backend) Delete(context.Context, string) error { return errReadOnly }

// GetMeta is not supported.
func (*Backend) GetMeta(context.Context, string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported.
func (*Backend) SetMeta(context.Context, string, vmeta.Meta) error { return backend.ErrNotSupported }

// ListMeta is not supported.
func (*Backend) ListMeta(context.Context, string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported.
func (*Backend) GetVersioned(context.Context, string, int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported.
func (*Backend) SetVersioned(context.Context, string, int, []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported.
func (*Backend) DeleteVersioned(context.Context, string, int) error {
	return backend.ErrNotSupported
}

// Close does nothing: no plaintext or key is kept between calls.
func (*Backend) Close() error { return nil }
