package kek

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	keychainService = "keylatch-vault-kek"
	itemLabel       = "Keylatch vault KEK"

	// A locked macOS keychain or Secret Service collection may show an unlock
	// prompt, so allow time for a human to answer it.
	identityStoreTimeout = 60 * time.Second

	keychainItemNotFoundExit = 44
)

type identityRunner func(ctx context.Context, stdin []byte, name string, args ...string) (stdout, stderr []byte, err error)

func execIdentityRunner(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: name is the resolved security/secret-tool binary; args are fixed or validated
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// DefaultIdentityStore returns the OS keyring for this platform, or nil when
// none is supported or reachable from this session.
func DefaultIdentityStore() IdentityStore {
	switch runtime.GOOS {
	case "darwin":
		const bin = "/usr/bin/security"
		if _, err := os.Stat(bin); err == nil {
			return &keychainIdentityStore{bin: bin, run: execIdentityRunner}
		}
	case "linux", "freebsd", "openbsd", "netbsd":
		bin, err := exec.LookPath("secret-tool")
		if err != nil || !sessionBusConfigured(os.Getenv) {
			return nil
		}
		return &secretServiceIdentityStore{bin: bin, run: execIdentityRunner}
	}
	return nil
}

func sessionBusConfigured(getenv func(string) string) bool {
	if getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	runtimeDir := getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(runtimeDir, "bus"))
	return err == nil
}

// keychainIdentityStore keeps the identity as a macOS login-keychain generic
// password. The secret reaches `security` on stdin through its interactive
// mode so it never appears in a process argument list.
type keychainIdentityStore struct {
	bin string
	run identityRunner
}

func (s *keychainIdentityStore) Name() string { return "macos-keychain" }

func (s *keychainIdentityStore) Load(account string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	out, stderr, err := s.run(ctx, nil, s.bin, "find-generic-password", "-s", keychainService, "-a", account, "-w")
	if err != nil {
		if exitCode(err) == keychainItemNotFoundExit {
			return nil, ErrIdentityNotFound
		}
		return nil, commandError("security find-generic-password", err, stderr)
	}
	return decodeIdentity(out)
}

func (s *keychainIdentityStore) Store(account string, identity []byte) error {
	if err := validAccount(account); err != nil {
		return err
	}
	line := []byte(fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		keychainService, account, hex.EncodeToString(identity)))
	defer zero(line)
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	// `security -i` can exit 0 when the inner command fails; callers verify
	// the item by reading it back.
	if _, stderr, err := s.run(ctx, line, s.bin, "-i"); err != nil {
		return commandError("security add-generic-password", err, stderr)
	}
	return nil
}

func (s *keychainIdentityStore) Delete(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	_, stderr, err := s.run(ctx, nil, s.bin, "delete-generic-password", "-s", keychainService, "-a", account)
	if err != nil {
		if exitCode(err) == keychainItemNotFoundExit {
			return ErrIdentityNotFound
		}
		return commandError("security delete-generic-password", err, stderr)
	}
	return nil
}

// secretServiceIdentityStore keeps the identity in the freedesktop Secret
// Service (GNOME Keyring, KWallet) through libsecret's secret-tool, which
// reads the secret from stdin.
type secretServiceIdentityStore struct {
	bin string
	run identityRunner
}

func (s *secretServiceIdentityStore) Name() string { return "secret-service" }

func (s *secretServiceIdentityStore) Load(account string) ([]byte, error) {
	if err := validAccount(account); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	out, stderr, err := s.run(ctx, nil, s.bin, "lookup", "application", "keylatch", "purpose", "kek", "account", account)
	if err != nil {
		// secret-tool exits 1 silently when no item matches.
		if exitCode(err) == 1 && len(bytes.TrimSpace(stderr)) == 0 && len(bytes.TrimSpace(out)) == 0 {
			return nil, ErrIdentityNotFound
		}
		return nil, commandError("secret-tool lookup", err, stderr)
	}
	return decodeIdentity(out)
}

func (s *secretServiceIdentityStore) Store(account string, identity []byte) error {
	if err := validAccount(account); err != nil {
		return err
	}
	secret := []byte(hex.EncodeToString(identity))
	defer zero(secret)
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	if _, stderr, err := s.run(ctx, secret, s.bin, "store", "--label="+itemLabel, "application", "keylatch", "purpose", "kek", "account", account); err != nil {
		return commandError("secret-tool store", err, stderr)
	}
	return nil
}

func (s *secretServiceIdentityStore) Delete(account string) error {
	if err := validAccount(account); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), identityStoreTimeout)
	defer cancel()
	if _, stderr, err := s.run(ctx, nil, s.bin, "clear", "application", "keylatch", "purpose", "kek", "account", account); err != nil {
		return commandError("secret-tool clear", err, stderr)
	}
	return nil
}

func exitCode(err error) int {
	var ee interface{ ExitCode() int }
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func commandError(what string, err error, stderr []byte) error {
	if msg := strings.TrimSpace(string(stderr)); msg != "" {
		return fmt.Errorf("%s: %w: %s", what, err, msg)
	}
	return fmt.Errorf("%s: %w", what, err)
}
