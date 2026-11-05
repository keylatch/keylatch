//go:build darwin

package keychain_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/keychain"
)

const fakeSecurityScript = `#!/bin/sh
# Records the argument list and any stdin script of every call, and answers
# the reads the backend makes.
printf '%%s\n' "$*" >> '%[1]s'
if [ "$1" = "-i" ]; then
  cat >> '%[2]s'
  exit 0
fi
case "$*" in
  *"-s keylatch-keychain -a unlock -w"*) echo "unlock-password-0123456789" ;;
  *"-s keylatch-_manifest"*) echo '{"version":1,"items":[{"connection":"svc","fields":["field"]}]}' ;;
  *"-s keylatch-svc -a field -w"*) echo "stored-secret-value-9876543210" ;;
esac
exit 0
`

// No secret value and no password reaches the argument list of security: they
// go over stdin through `security -i`. The fake security binary records both.
func TestNoSecretsOnArgv(t *testing.T) {
	dir := t.TempDir()
	argvLog := filepath.Join(dir, "argv.log")
	stdinLog := filepath.Join(dir, "stdin.log")
	bin := filepath.Join(dir, "security")
	if err := os.WriteFile(bin, []byte(strings.NewReplacer("%[1]s", argvLog, "%[2]s", stdinLog, "%%", "%").Replace(fakeSecurityScript)), 0o755); err != nil {
		t.Fatal(err)
	}

	const (
		secret   = "brand-new-secret-value-5550123"
		unlockPW = "unlock-password-0123456789"
		stored   = "stored-secret-value-9876543210"
	)
	b, err := keychain.Open(keychain.Options{
		KeychainPath: filepath.Join(dir, "k.keychain-db"),
		LockPath:     filepath.Join(dir, "k.lock"),
		SecurityBin:  bin,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	if err := b.Set(ctx, "default/svc/field", []byte(secret), backend.Meta{Path: "default/svc/field", Backend: "keychain", Version: 1}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := b.RepairACL(ctx); err != nil {
		t.Fatalf("RepairACL: %v", err)
	}
	if err := b.RepairItemACLs(ctx); err != nil {
		t.Fatalf("RepairItemACLs: %v", err)
	}
	if err := b.ForceReinit(ctx, "default"); err != nil {
		t.Fatalf("ForceReinit: %v", err)
	}

	argv, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := os.ReadFile(stdinLog)
	if err != nil {
		t.Fatal(err)
	}

	// The password ForceReinit generated is visible in the stdin script only.
	m := regexp.MustCompile(`create-keychain -p "([^"]+)"`).FindStringSubmatch(string(stdin))
	if m == nil {
		t.Fatalf("create-keychain did not read its password from stdin:\n%s", stdin)
	}
	for _, secretText := range []string{secret, unlockPW, stored, m[1]} {
		for _, form := range []string{secretText, hex.EncodeToString([]byte(secretText))} {
			if strings.Contains(string(argv), form) {
				t.Errorf("a secret reached security's argument list:\n%s", argv)
			}
		}
	}
	for _, line := range strings.Split(string(argv), "\n") {
		if strings.Contains(line, "unlock-keychain") || strings.Contains(line, "create-keychain") || strings.Contains(line, " -X ") {
			t.Errorf("security was started with password or secret arguments: %q", line)
		}
		for _, f := range strings.Fields(line) {
			if f == "-p" {
				t.Errorf("security was started with -p: %q", line)
			}
		}
	}

	// The secrets did arrive over stdin, hex-encoded for values.
	for _, want := range []string{
		`add-generic-password -U -s "keylatch-svc" -a "field" -X ` + hex.EncodeToString([]byte(secret)),
		`unlock-keychain -p "` + unlockPW + `"`,
		hex.EncodeToString([]byte(stored)),
	} {
		if !strings.Contains(string(stdin), want) {
			t.Errorf("stdin script lacks %q", want)
		}
	}
}
