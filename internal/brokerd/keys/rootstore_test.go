package keys

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type xorSealer struct{ failOpen, failSeal bool }

func (xorSealer) Name() string { return "test sealer" }
func (x xorSealer) Seal(p []byte) ([]byte, error) {
	if x.failSeal {
		return nil, errors.New("seal failed")
	}
	out := append([]byte(nil), p...)
	for i := range out {
		out[i] ^= 0xA5
	}
	return out, nil
}

func (x xorSealer) Open(b []byte) ([]byte, error) {
	if x.failOpen {
		return nil, errors.New("not this account")
	}
	return x.Seal(b)
}

func TestSealedFileRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Sealer
		want string
	}{{"plain file", nil, "root file"}, {"sealed", xorSealer{}, "test sealer"}} {
		t.Run(tc.name, func(t *testing.T) {
			store := SealedFile{Path: filepath.Join(t.TempDir(), "sub", "root.key"), Sealer: tc.s}
			if store.Name() != tc.want {
				t.Fatalf("name = %q", store.Name())
			}
			if _, err := store.Load(); !errors.Is(err, ErrNoRoot) {
				t.Fatalf("no root yet = %v", err)
			}
			rd := bytes.NewReader(bytes.Repeat([]byte{7}, 64))
			created, err := store.Create(rd)
			if err != nil || !created {
				t.Fatalf("create = %v, %v", created, err)
			}
			got, err := store.Load()
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte{7}, 32)) {
				t.Fatalf("load = %x, %v", got, err)
			}
			info, _ := os.Stat(store.Path)
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0o400 {
				t.Fatalf("mode = %v", info.Mode().Perm())
			}
			if tc.s != nil {
				raw, _ := os.ReadFile(store.Path)
				if bytes.Contains(raw, bytes.Repeat([]byte{7}, 32)) {
					t.Fatal("the sealed file holds the root in clear")
				}
			}
			again, err := store.Create(bytes.NewReader(bytes.Repeat([]byte{8}, 64)))
			if err != nil || again {
				t.Fatalf("a second create replaced the root: %v, %v", again, err)
			}
			if got2, _ := store.Load(); !bytes.Equal(got2, got) {
				t.Fatal("the root changed")
			}
		})
	}
}

func TestSealedFileFailures(t *testing.T) {
	dir := t.TempDir()
	short := SealedFile{Path: filepath.Join(dir, "short")}
	if err := os.WriteFile(short.Path, []byte("tiny"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := short.Load(); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("a short root = %v", err)
	}
	other := SealedFile{Path: filepath.Join(dir, "o"), Sealer: xorSealer{}}
	if _, err := other.Create(nil); err != nil {
		t.Fatal(err)
	}
	other.Sealer = xorSealer{failOpen: true}
	if _, err := other.Load(); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("a root another account sealed = %v", err)
	}
	if _, err := (SealedFile{Path: filepath.Join(dir, "s"), Sealer: xorSealer{failSeal: true}}).Create(nil); err == nil {
		t.Fatal("a seal failure was ignored")
	}
	if _, err := (SealedFile{Path: filepath.Join(dir, "r")}).Create(bytes.NewReader([]byte{1})); err == nil {
		t.Fatal("a short random source was accepted")
	}
	// Handing the file over fails: nothing stays behind.
	own := SealedFile{Path: filepath.Join(dir, "own"), Own: func(string) error { return errors.New("no such user") }}
	if _, err := own.Create(nil); err == nil {
		t.Fatal("a failed hand-over was ignored")
	}
	if _, err := os.Stat(own.Path); err == nil {
		t.Fatal("the root stayed behind after a failed hand-over")
	}
	// A tiny sealed payload is refused even when it opens.
	tiny := SealedFile{Path: filepath.Join(dir, "tiny"), Sealer: xorSealer{}}
	if err := os.WriteFile(tiny.Path, []byte{1, 2}, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := tiny.Load(); !errors.Is(err, ErrNoRoot) {
		t.Fatalf("a short sealed root = %v", err)
	}
	if _, err := (SealedFile{Path: dir}).Load(); err == nil {
		t.Fatal("a directory loaded as a root")
	}
	var _ RootStore = SealedFile{}
}
