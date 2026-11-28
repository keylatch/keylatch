package backend

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCheckSupported_EnabledManagersNeedNoOptIn(t *testing.T) {
	t.Setenv(AllowUnsupportedEnv, "")
	for _, id := range []string{"op", "bw"} {
		if err := CheckSupported(id); err != nil {
			t.Errorf("CheckSupported(%q) = %v, want nil", id, err)
		}
	}
}

func TestCheckSupported_RefusesWithoutOptIn(t *testing.T) {
	t.Setenv(AllowUnsupportedEnv, "")
	for _, id := range []string{"file", "vault", "lastpass"} {
		err := CheckSupported(id)
		if !errors.Is(err, ErrUnsupportedBackend) {
			t.Fatalf("CheckSupported(%q) = %v, want ErrUnsupportedBackend", id, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, `"`+id+`"`) || !strings.Contains(msg, "not supported") || !strings.Contains(msg, "bw, op") {
			t.Errorf("message for %q does not name the backend and the supported managers: %s", id, msg)
		}
	}
}

func TestCheckSupported_UnmarkedBackendsIgnoreTheOptIn(t *testing.T) {
	t.Setenv(AllowUnsupportedEnv, "keeper,proton-pass,op-connect,keychain")
	for _, id := range []string{"keeper", "proton-pass", "op-connect", "keychain"} {
		err := CheckSupported(id)
		if !errors.Is(err, ErrUnsupportedBackend) {
			t.Fatalf("CheckSupported(%q) = %v, want ErrUnsupportedBackend", id, err)
		}
		if strings.Contains(err.Error(), AllowUnsupportedEnv) {
			t.Errorf("message for %q suggests the opt-in: %s", id, err)
		}
	}
}

func TestCheckSupported_OptInIsPerBackendAndWarnsOnce(t *testing.T) {
	var out bytes.Buffer
	oldOut := warnOut
	warnOut = &out
	warnedMu.Lock()
	warned = map[string]bool{}
	warnedMu.Unlock()
	t.Cleanup(func() { warnOut = oldOut })

	t.Setenv(AllowUnsupportedEnv, " file , awssm")
	for _, id := range []string{"file", "file", "aws-sm"} {
		if err := CheckSupported(id); err != nil {
			t.Fatalf("CheckSupported(%q) with opt-in = %v", id, err)
		}
	}
	if err := CheckSupported("vault"); !errors.Is(err, ErrUnsupportedBackend) {
		t.Errorf("opt-in for file and aws-sm must not open vault: %v", err)
	}
	if got := strings.Count(out.String(), `using backend "file"`); got != 1 {
		t.Errorf("file notice printed %d times, want once:\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), `using backend "aws-sm"`) || !strings.Contains(out.String(), "Unproven:") {
		t.Errorf("aws-sm notice missing or does not say what is unproven:\n%s", out.String())
	}
}

func TestUnsupportedError_NamesTheBackendAndItsDoc(t *testing.T) {
	t.Setenv(AllowUnsupportedEnv, "")
	cases := []struct {
		name, doc, optIn string
		wantOptIn        bool
	}{
		{"file", "docs/backends/moving-off-file.md", AllowUnsupportedEnv + "=file", true},
		{"vault", "docs/backends/moving-off-file.md#other-opt-in-backends", AllowUnsupportedEnv + "=vault", true},
		{"keychain", "docs/backends/moving-off-file.md#backends-that-cannot-be-enabled", "", false},
	}
	for _, c := range cases {
		err := CheckSupported(c.name)
		var ue *UnsupportedError
		if !errors.As(err, &ue) {
			t.Fatalf("%s: want UnsupportedError, got %v", c.name, err)
		}
		msg := err.Error()
		if ue.OptIn != c.wantOptIn || !strings.Contains(msg, `"`+c.name+`"`) || !strings.HasSuffix(msg, c.doc) {
			t.Errorf("%s: unexpected message %q", c.name, msg)
		}
		if strings.Contains(msg, AllowUnsupportedEnv+"=") != c.wantOptIn {
			t.Errorf("%s: opt-in hint mismatch in %q", c.name, msg)
		}
	}
}

func TestOptInEnvValue_KeepsOnlyBackendsTheManifestOpensToOptIn(t *testing.T) {
	t.Setenv(AllowUnsupportedEnv, " file, keychain,awssm,file,bw,bogus")
	if got := OptInEnvValue(); got != "file,aws-sm" {
		t.Errorf("OptInEnvValue = %q, want file,aws-sm", got)
	}
	t.Setenv(AllowUnsupportedEnv, "")
	if got := OptInEnvValue(); got != "" {
		t.Errorf("OptInEnvValue = %q, want empty", got)
	}
}
