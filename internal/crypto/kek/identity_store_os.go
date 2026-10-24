package kek

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
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
	return runBounded(ctx, stdin, name, args...)
}

// osKeyringDisabled reports that no OS keyring may be used. Only the
// end-to-end test build sets it.
var osKeyringDisabled = func() bool { return false }

// DefaultIdentityStore returns the OS keyring for this platform, or nil when
// none is supported or reachable from this session.
func DefaultIdentityStore() IdentityStore {
	if osKeyringDisabled() {
		return nil
	}
	switch runtime.GOOS {
	case "darwin":
		return newMacOSIdentityStore()
	case "linux", "freebsd", "openbsd", "netbsd":
		if !sessionBusConfigured(os.Getenv) {
			return nil
		}
		return newSecretServiceIdentityStore()
	case "windows":
		return platformIdentityStore()
	}
	return nil
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
	defer zero(out)
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
