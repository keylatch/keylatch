package pkcs11_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/trust"
	"github.com/keylatch/keylatch/internal/trust/pkcs11"
)

func trpClearLLMEnv(t *testing.T) {
	t.Helper()
	for _, s := range llmcontext.Signals {
		t.Setenv(s.EnvKey, "")
	}
}

// trpEnv sets HOME and writes a fake module file plus an HMAC-signed allowlist entry for it.
func trpEnv(t *testing.T, pinHash bool) (modPath string, kek func([]byte) []byte) {
	t.Helper()
	trpClearLLMEnv(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	modPath = filepath.Join(t.TempDir(), "libfake-pkcs11.so")
	content := []byte("\x7fELF fake module")
	if err := os.WriteFile(modPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	kek = makeTestHMAC([]byte("kek-hmac-key-for-tests"))
	e := pkcs11.ModuleEntry{ModulePath: modPath, Vendor: "Test"}
	if pinHash {
		sum := sha256.Sum256(content)
		e.SHA256Hex = hex.EncodeToString(sum[:])
	}
	e.HMAC = pkcs11.MakeEntryHMAC(e, kek)
	if err := pkcs11.SaveAllowlist([]pkcs11.ModuleEntry{e}); err != nil {
		t.Fatal(err)
	}
	return modPath, kek
}

func TestNewOpensPinnedAllowlistedModule(t *testing.T) {
	mod, kek := trpEnv(t, true)
	a, err := pkcs11.New(pkcs11.Options{ModulePath: mod, SlotLabel: "token0", KekHMAC: kek})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.ID() != "pkcs11:"+mod+":token0" || a.Type() != trust.RootPKCS11 {
		t.Fatalf("ID=%q Type=%q", a.ID(), a.Type())
	}
}

func TestNewAllowsUnpinnedModuleWithWarning(t *testing.T) {
	mod, kek := trpEnv(t, false)
	if _, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek, Label: "L"}); err != nil {
		t.Fatalf("New: %v", err)
	}
}

func TestNewRejectsModuleOutsideAllowlist(t *testing.T) {
	mod, _ := trpEnv(t, true)
	// Without the KEK the signed user entry is dropped, so only defaults remain.
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod})
	if !errors.Is(err, trust.ErrModuleNotAllowlisted) || !strings.Contains(err.Error(), mod) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewRejectsModuleHashMismatch(t *testing.T) {
	mod, kek := trpEnv(t, true)
	if err := os.WriteFile(mod, []byte("swapped binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek})
	if !errors.Is(err, trust.ErrModuleHashMismatch) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewPinnedModuleMissingOnDisk(t *testing.T) {
	mod, kek := trpEnv(t, true)
	if err := os.Remove(mod); err != nil {
		t.Fatal(err)
	}
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek})
	if err == nil || !strings.Contains(err.Error(), "open module") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewUnpinnedModuleMissingIsUnavailable(t *testing.T) {
	mod, kek := trpEnv(t, false)
	if err := os.Remove(mod); err != nil {
		t.Fatal(err)
	}
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek})
	if !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "module not found") {
		t.Fatalf("err = %v", err)
	}
}

func TestNewCorruptAllowlistFallsBackToDefaults(t *testing.T) {
	mod, kek := trpEnv(t, true)
	home, _ := os.UserHomeDir()
	if err := os.WriteFile(filepath.Join(home, ".keylatch", "trust-allowlist.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pkcs11.LoadAllowlist(kek); err == nil || !strings.Contains(err.Error(), "parse allowlist") {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek})
	if !errors.Is(err, trust.ErrModuleNotAllowlisted) {
		t.Fatalf("err = %v", err)
	}
}

func TestNewEnvPINBlockedInLLMSession(t *testing.T) {
	mod, kek := trpEnv(t, true)
	t.Setenv("CLAUDECODE", "1")
	_, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek, PINSource: "env:KEYLATCH_PKCS11_PIN"})
	if !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Fatalf("env PIN: err = %v", err)
	}
	if _, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek, PINSource: "prompt"}); err != nil {
		t.Fatalf("prompt PIN in LLM session: %v", err)
	}
}

func TestStubOperationsReportUnavailable(t *testing.T) {
	mod, kek := trpEnv(t, true)
	a, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek, PINSource: "env:KEYLATCH_PKCS11_PIN"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	dek := []byte{9, 9}
	if _, err := a.Wrap(ctx, dek); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Wrap: %v", err)
	}
	if dek[0] != 0 || dek[1] != 0 {
		t.Error("Wrap must zero the DEK")
	}
	if _, err := a.Unwrap(ctx, nil); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Unwrap: %v", err)
	}
	if _, _, err := a.Sign(ctx, nil); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Sign: %v", err)
	}
	if err := a.Verify(ctx, nil, nil, nil); !errors.Is(err, trust.ErrRootUnavailable) {
		t.Errorf("Verify: %v", err)
	}
	if att, err := a.Attest(ctx); err != nil || att.Format != "pkcs11" {
		t.Errorf("Attest = %+v, %v", att, err)
	}
	if err := a.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	for c, want := range map[trust.Capability]bool{
		trust.CapWrap: true, trust.CapSignChallenge: true, trust.CapAttestation: true, trust.CapHardwareBound: true,
		trust.CapMTLSClientAuth: false, trust.CapLaunchdSafe: false, trust.CapUserPresence: false, trust.Capability(1 << 20): false,
	} {
		if a.Has(c) != want {
			t.Errorf("Has(%d) = %v", c, !want)
		}
	}
}

func TestPresenceProof(t *testing.T) {
	mod, kek := trpEnv(t, true)
	ctx := context.Background()

	a, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.RequirePresence(ctx, "reveal")
	if err != nil || p.Method != "pkcs11-pin" || p.RootID != a.ID() || p.ConfirmedAt.IsZero() {
		t.Fatalf("proof = %+v, %v", p, err)
	}
	if err := a.VerifyPresenceProof(ctx, p); err != nil {
		t.Fatal(err)
	}
	if err := a.VerifyPresenceProof(ctx, trust.PresenceProof{}); err == nil {
		t.Fatal("empty proof accepted")
	}

	hm := func(b []byte) []byte { return append([]byte("h:"), b...) }
	b, err := pkcs11.New(pkcs11.Options{ModulePath: mod, KekHMAC: kek, HMACFunc: hm})
	if err != nil {
		t.Fatal(err)
	}
	p, err = b.RequirePresence(ctx, "reveal")
	if err != nil || p.RootID != base64.RawURLEncoding.EncodeToString(hm([]byte(b.ID()))) {
		t.Fatalf("hmac proof = %+v, %v", p, err)
	}

	t.Setenv("CLAUDECODE", "1")
	if _, err := b.RequirePresence(ctx, "reveal"); !errors.Is(err, trust.ErrLLMSessionBlocked) {
		t.Fatalf("LLM session: %v", err)
	}
}

func TestRegisteredFactory(t *testing.T) {
	trpEnv(t, true)
	if _, err := trust.New(trust.RootSpec{Type: trust.RootPKCS11}); !errors.Is(err, trust.ErrRootUnavailable) || !strings.Contains(err.Error(), "module_path not set") {
		t.Fatalf("no module: err = %v", err)
	}
	_, err := trust.New(trust.RootSpec{Type: trust.RootPKCS11, Extra: map[string]any{"module_path": "/opt/evil.so", "slot_label": "s"}})
	if !errors.Is(err, trust.ErrModuleNotAllowlisted) {
		t.Fatalf("evil module: err = %v", err)
	}

	// Default allowlist entries are unpinned; the factory reaches the on-disk check.
	r, err := trust.New(trust.RootSpec{Type: trust.RootPKCS11, Label: "x", Extra: map[string]any{"module_path": "/usr/lib/softhsm/libsofthsm2.so", "slot_label": "s"}})
	if err == nil {
		if r.ID() != "pkcs11:/usr/lib/softhsm/libsofthsm2.so:s" {
			t.Fatalf("ID = %q", r.ID())
		}
	} else if !errors.Is(err, trust.ErrRootUnavailable) {
		t.Fatalf("default module: err = %v", err)
	}
}

func TestComputeModuleHashAndSaveErrors(t *testing.T) {
	mod, _ := trpEnv(t, true)
	h, err := pkcs11.ComputeModuleHash(mod)
	sum := sha256.Sum256([]byte("\x7fELF fake module"))
	if err != nil || h != hex.EncodeToString(sum[:]) {
		t.Fatalf("ComputeModuleHash = %q, %v", h, err)
	}
	if err := pkcs11.VerifyModuleHash(mod, strings.ToUpper(h)); err != nil {
		t.Fatalf("hash comparison should be case-insensitive: %v", err)
	}
	if _, err := pkcs11.ComputeModuleHash(filepath.Join(t.TempDir(), "nope")); err == nil || !strings.Contains(err.Error(), "pkcs11: open") {
		t.Fatalf("missing: %v", err)
	}
	dir := t.TempDir()
	if _, err := pkcs11.ComputeModuleHash(dir); err == nil || !strings.Contains(err.Error(), "pkcs11: hash") {
		t.Fatalf("directory: %v", err)
	}
	if err := pkcs11.VerifyModuleHash(dir, "00"); err == nil || !strings.Contains(err.Error(), "hash module") {
		t.Fatalf("verify directory: %v", err)
	}

	home, _ := os.UserHomeDir()
	info, err := os.Stat(filepath.Join(home, ".keylatch", "trust-allowlist.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("allowlist perms = %v, %v", info.Mode().Perm(), err)
	}

	blocked := t.TempDir()
	t.Setenv("HOME", blocked)
	if err := os.WriteFile(filepath.Join(blocked, ".keylatch"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := pkcs11.SaveAllowlist(nil); err == nil || !strings.Contains(err.Error(), "pkcs11: mkdir") {
		t.Fatalf("SaveAllowlist mkdir: %v", err)
	}

	t.Setenv("HOME", t.TempDir())
	home, _ = os.UserHomeDir()
	if err := os.MkdirAll(filepath.Join(home, ".keylatch", "trust-allowlist.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pkcs11.SaveAllowlist(nil); err == nil || !strings.Contains(err.Error(), "write allowlist") {
		t.Fatalf("SaveAllowlist write: %v", err)
	}
	if _, err := pkcs11.LoadAllowlist(nil); err == nil || !strings.Contains(err.Error(), "read allowlist") {
		t.Fatalf("LoadAllowlist read: %v", err)
	}
}

func TestLoadAllowlistDropsMalformedHMAC(t *testing.T) {
	trpEnv(t, true)
	kek := makeTestHMAC([]byte("kek-hmac-key-for-tests"))
	e := pkcs11.ModuleEntry{ModulePath: "/opt/m.so", HMAC: "zz-not-hex"}
	if err := pkcs11.SaveAllowlist([]pkcs11.ModuleEntry{e, {ModulePath: "/opt/n.so"}}); err != nil {
		t.Fatal(err)
	}
	entries, err := pkcs11.LoadAllowlist(kek)
	if err != nil {
		t.Fatal(err)
	}
	if pkcs11.IsAllowed(entries, "/opt/m.so") || pkcs11.IsAllowed(entries, "/opt/n.so") {
		t.Fatal("entries with malformed or missing HMAC must be dropped")
	}
}
