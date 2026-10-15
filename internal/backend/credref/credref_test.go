package credref

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

func testKEK(t *testing.T, pass string) kek.KEK {
	t.Helper()
	k, err := kek.PassphraseKEK([]byte(pass), make([]byte, 32), argon2.Params{Time: 1, Memory: 64 * 1024, Threads: 1, SaltLen: 32, KeyLen: 32})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSaveLoadRoundTripIsWrapped(t *testing.T) {
	dir := t.TempDir()
	env := llmcontext.Lookup(func(k string) string {
		if k == "KEYLATCH_CONFIG_DIR" {
			return dir
		}
		return ""
	})
	k := testKEK(t, "a")
	if err := Save(env, k, "ref-1", map[string]string{"token": "super-secret-token"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(Path(env, "ref-1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("super-secret-token")) {
		t.Fatal("credential stored in the clear")
	}
	got, err := Load(env, k, "ref-1")
	if err != nil || got["token"] != "super-secret-token" {
		t.Fatalf("Load = %v, %v", got, err)
	}
	if _, err := Load(env, testKEK(t, "b"), "ref-1"); err == nil {
		t.Fatal("loaded under a different KEK")
	}
	if _, err := Load(env, k, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing ref: %v", err)
	}
	for _, bad := range []string{"", "../x", "a/b", "."} {
		if err := Save(env, k, bad, nil); err == nil {
			t.Errorf("Save accepted reference %q", bad)
		}
	}
}
