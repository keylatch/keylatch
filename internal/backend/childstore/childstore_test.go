//go:build unix

package childstore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/vault/meta"
)

var childCanary = "canary" + "-childstore-" + "7b31"

type fakeSource struct{ err error }

func (f fakeSource) Get(_ context.Context, p string) ([]byte, backend.Meta, error) {
	if f.err != nil {
		return nil, backend.Meta{}, f.err
	}
	if p != "default/ai/demo/api_key" {
		return nil, backend.Meta{}, backend.ErrNotFound
	}
	return []byte(childCanary), backend.Meta{Path: p, Version: 3, Backend: "broker"}, nil
}

func (f fakeSource) List(_ context.Context, prefix string) ([]backend.Entry, error) {
	if f.err != nil {
		return nil, f.err
	}
	return []backend.Entry{{Meta: backend.Meta{Path: prefix + "x"}, Exists: true}}, nil
}

func connect(t *testing.T, src Source) *Store {
	t.Helper()
	conn, child, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go Serve(ctx, conn, src)
	st, ok, err := FromEnv(func(string) string { return fmt.Sprint(child.Fd()) })
	if err != nil || !ok {
		t.Fatalf("FromEnv: %v %v", ok, err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestChildStoreReadsAndNeverWrites(t *testing.T) {
	st := connect(t, fakeSource{})
	ctx := context.Background()
	v, m, err := st.Get(ctx, "default/ai/demo/api_key")
	if err != nil || string(v) != childCanary || m.Version != 3 {
		t.Fatalf("Get = %q %+v %v", v, m, err)
	}
	if _, _, err := st.Get(ctx, "default/ai/demo/missing"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	es, err := st.List(ctx, "default/")
	if err != nil || len(es) != 1 || es[0].Path != "default/x" {
		t.Fatalf("List = %+v %v", es, err)
	}
	if err := st.Set(ctx, "p", []byte("v"), backend.Meta{}); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Set = %v", err)
	}
	if err := st.Delete(ctx, "p"); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("Delete = %v", err)
	}
	if st.Name() != "broker" || st.ID() == "" || st.Capabilities() != nil {
		t.Fatal("identity")
	}
	if _, err := st.GetMeta(ctx, "p"); !errors.Is(err, backend.ErrNotSupported) {
		t.Fatal("GetMeta")
	}
	if st.SetMeta(ctx, "p", meta.Meta{}) == nil || st.SetVersioned(ctx, "p", 1, nil) == nil || st.DeleteVersioned(ctx, "p", 1) == nil {
		t.Fatal("versioned writes were accepted")
	}
	if _, err := st.ListMeta(ctx, ""); err == nil {
		t.Fatal("ListMeta")
	}
	if _, err := st.GetVersioned(ctx, "p", 1); err == nil {
		t.Fatal("GetVersioned")
	}
}

func TestChildStoreSourceFailure(t *testing.T) {
	st := connect(t, fakeSource{err: errors.New("sealed")})
	if _, _, err := st.Get(context.Background(), "p"); err == nil || !strings.Contains(err.Error(), "sealed") {
		t.Fatalf("Get = %v", err)
	}
	if _, err := st.List(context.Background(), "p"); err == nil {
		t.Fatal("List hid a failure")
	}
}

func TestChildStoreServerGone(t *testing.T) {
	conn, child, err := Pair()
	if err != nil {
		t.Fatal(err)
	}
	st, _, err := FromEnv(func(string) string { return fmt.Sprint(child.Fd()) })
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, _, err := st.Get(context.Background(), "p"); err == nil {
		t.Fatal("Get succeeded with the broker gone")
	}
}

func TestServeRefusesBadRequests(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go Serve(context.Background(), b, fakeSource{})
	for _, line := range []string{"not json\n", `{"op":"delete"}` + "\n"} {
		if _, err := a.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 512)
		n, err := a.Read(buf)
		if err != nil || !strings.Contains(string(buf[:n]), `"ok":false`) {
			t.Fatalf("reply = %q %v", buf[:n], err)
		}
	}
	big := strings.Repeat("a", maxFrame+10) + "\n"
	go func() { _, _ = a.Write([]byte(big)) }()
	buf := make([]byte, 16)
	if _, err := a.Read(buf); err == nil {
		t.Fatal("an oversize frame was answered")
	}
}

func TestFromEnv(t *testing.T) {
	if _, ok, err := FromEnv(func(string) string { return "" }); ok || err != nil {
		t.Fatalf("unset: %v %v", ok, err)
	}
	for _, v := range []string{"abc", "2", "-1"} {
		if _, ok, err := FromEnv(func(string) string { return v }); !ok || err == nil {
			t.Fatalf("%q: %v %v", v, ok, err)
		}
	}
	if _, ok, err := FromEnv(func(string) string { return "999" }); !ok || err == nil {
		t.Fatalf("closed descriptor: %v %v", ok, err)
	}
}
