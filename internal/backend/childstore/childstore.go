// Package childstore lets a verb the broker runs for a user read that user's
// partition without holding any key. The broker passes the child one end of a
// socket pair on a fixed descriptor and answers reads from its own store; the
// child can read and list, never write or delete.
package childstore

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

// EnvFD names the environment variable that carries the descriptor.
const EnvFD = "KEYLATCH_BROKER_STORE_FD"

// ChildFD is the descriptor the child inherits (the first extra file).
const ChildFD = 3

// maxFrame bounds one request or reply.
const maxFrame = 1 << 20

// ErrReadOnly is returned for a write through a child's store.
var ErrReadOnly = errors.New("childstore: the broker store is read-only here; writes go through the broker")

// Source is what the broker answers reads from.
type Source interface {
	Get(ctx context.Context, path string) ([]byte, backend.Meta, error)
	List(ctx context.Context, prefix string) ([]backend.Entry, error)
}

type request struct {
	Op     string `json:"op"`
	Path   string `json:"path,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

type reply struct {
	OK       bool            `json:"ok"`
	NotFound bool            `json:"not_found,omitempty"`
	Error    string          `json:"error,omitempty"`
	Value    []byte          `json:"value,omitempty"`
	Meta     backend.Meta    `json:"meta,omitempty"`
	Entries  []backend.Entry `json:"entries,omitempty"`
}

// Serve answers requests on conn until it closes or ctx ends.
func Serve(ctx context.Context, conn net.Conn, src Source) {
	defer conn.Close()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	r := bufio.NewReaderSize(conn, 64<<10)
	enc := json.NewEncoder(conn)
	for {
		line, err := readLine(r)
		if err != nil {
			return
		}
		var req request
		var rep reply
		if err := json.Unmarshal(line, &req); err != nil {
			rep = reply{Error: "unreadable request"}
		} else {
			rep = answer(ctx, src, req)
		}
		err = enc.Encode(rep)
		clear(rep.Value)
		if err != nil {
			return
		}
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			return nil, err
		}
		out = append(out, chunk...)
		if len(out) > maxFrame {
			return nil, errors.New("childstore: frame too large")
		}
		if !isPrefix {
			return out, nil
		}
	}
}

func answer(ctx context.Context, src Source, req request) reply {
	switch req.Op {
	case "get":
		v, m, err := src.Get(ctx, req.Path)
		if err != nil {
			return failure(err)
		}
		return reply{OK: true, Value: v, Meta: m}
	case "list":
		es, err := src.List(ctx, req.Prefix)
		if err != nil {
			return failure(err)
		}
		return reply{OK: true, Entries: es}
	}
	return reply{Error: "unknown operation"}
}

func failure(err error) reply {
	if errors.Is(err, backend.ErrNotFound) {
		return reply{NotFound: true, Error: "secret not found"}
	}
	return reply{Error: err.Error()}
}

// Store is the child's side: a read-only backend over the descriptor.
type Store struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
	enc  *json.Encoder
}

// New wraps one end of the connection.
func New(conn net.Conn) *Store {
	return &Store{conn: conn, r: bufio.NewReaderSize(conn, 64<<10), enc: json.NewEncoder(conn)}
}

// FromEnv opens the store a broker passed this process, or reports false when
// there is none.
func FromEnv(lookup func(string) string) (*Store, bool, error) {
	raw := lookup(EnvFD)
	if raw == "" {
		return nil, false, nil
	}
	var fd int
	if _, err := fmt.Sscanf(raw, "%d", &fd); err != nil || fd < 3 {
		return nil, true, fmt.Errorf("childstore: %s is not a descriptor", EnvFD)
	}
	f := os.NewFile(uintptr(fd), "keylatch-broker-store")
	defer f.Close()
	conn, err := net.FileConn(f)
	if err != nil {
		return nil, true, fmt.Errorf("childstore: %w", err)
	}
	return New(conn), true, nil
}

func (s *Store) roundTrip(req request) (reply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.enc.Encode(req); err != nil {
		return reply{}, err
	}
	line, err := readLine(s.r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = errors.New("the broker closed the store connection")
		}
		return reply{}, err
	}
	var rep reply
	if err := json.Unmarshal(line, &rep); err != nil {
		return reply{}, err
	}
	clear(line)
	switch {
	case rep.NotFound:
		return reply{}, backend.ErrNotFound
	case !rep.OK:
		return reply{}, errors.New(strings.TrimSpace("childstore: " + rep.Error))
	}
	return rep, nil
}

func (*Store) Name() string                                            { return "broker" }
func (*Store) ID() string                                              { return "broker-child" }
func (*Store) Capabilities() []backend.Capability                      { return nil }
func (s *Store) Close() error                                          { return s.conn.Close() }
func (*Store) Set(context.Context, string, []byte, backend.Meta) error { return ErrReadOnly }
func (*Store) Delete(context.Context, string) error                    { return ErrReadOnly }

func (s *Store) Get(_ context.Context, path string) ([]byte, backend.Meta, error) {
	rep, err := s.roundTrip(request{Op: "get", Path: path})
	if err != nil {
		return nil, backend.Meta{}, err
	}
	return rep.Value, rep.Meta, nil
}

func (s *Store) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	rep, err := s.roundTrip(request{Op: "list", Prefix: prefix})
	if err != nil {
		return nil, err
	}
	return rep.Entries, nil
}

func (*Store) GetMeta(context.Context, string) (meta.Meta, error) {
	return meta.Meta{}, backend.ErrNotSupported
}
func (*Store) SetMeta(context.Context, string, meta.Meta) error { return backend.ErrNotSupported }
func (*Store) ListMeta(context.Context, string) ([]meta.Meta, error) {
	return nil, backend.ErrNotSupported
}
func (*Store) GetVersioned(context.Context, string, int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}
func (*Store) SetVersioned(context.Context, string, int, []byte) error {
	return backend.ErrNotSupported
}
func (*Store) DeleteVersioned(context.Context, string, int) error { return backend.ErrNotSupported }

var _ backend.Backend = (*Store)(nil)
