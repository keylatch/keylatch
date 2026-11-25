package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

const opServiceAccountEnv = "OP_SERVICE_ACCOUNT_TOKEN"

var credentialNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// opSARunner runs systemd-creds and op; tests substitute a fake.
var opSARunner kexec.CommandRunner = kexec.DefaultRunner

var resolveBinFunc = kexec.Resolve

// exportOPServiceAccountToken reads the systemd credential `name` from
// $CREDENTIALS_DIRECTORY and exports it as OP_SERVICE_ACCOUNT_TOKEN for this
// process (and the `op` children it starts). The value is never logged, put in
// an env file or passed on a command line.
func exportOPServiceAccountToken(name string) error {
	if !credentialNameRE.MatchString(name) {
		return fmt.Errorf("--op-service-account-credential %q: use the credential name (letters, digits, '.', '_', '-'), not a path", name)
	}
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return fmt.Errorf("--op-service-account-credential %q: CREDENTIALS_DIRECTORY is not set; run this under the systemd unit (LoadCredentialEncrypted=%s:<file>)", name, name)
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return fmt.Errorf("--op-service-account-credential %q: credential not readable: %w", name, err)
	}
	defer clear(data)
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return fmt.Errorf("--op-service-account-credential %q: credential is empty", name)
	}
	return os.Setenv(opServiceAccountEnv, tok)
}

// opWhoamiVerdict runs `op whoami` with the token already in the environment
// (or extraEnv) and returns a one-line verdict without any token material.
func opWhoamiVerdict(ctx context.Context, extraEnv []string) string {
	bin := os.Getenv("KEYLATCH_OP_BIN")
	if bin == "" {
		bin = resolveBinFunc("op")
	}
	if bin == "" {
		return "op binary not found; cannot verify"
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_, _, code, err := opSARunner.RunEnv(ctx, bin, []string{"whoami", "--format=json"}, nil, extraEnv)
	if err != nil || code != 0 {
		return "service account NOT authenticated (`op whoami` failed; the token may be revoked, expired or unreachable)"
	}
	return "service account authenticated via `op whoami` (token redacted)"
}

// checkSealedOPServiceAccount decrypts the sealed token for this call only and
// verifies it with `op whoami`. The token is passed to op through its
// environment and never printed.
func checkSealedOPServiceAccount(ctx context.Context, credFile string) string {
	bin := resolveBinFunc("systemd-creds")
	if bin == "" {
		return "systemd-creds not found; cannot decrypt the credential here"
	}
	out, _, code, err := opSARunner.Run(ctx, bin, []string{"decrypt", "--user", "--name=" + systemdCredentialOPSA, credFile, "-"}, nil)
	defer clear(out)
	tok := strings.TrimSpace(string(out))
	if err != nil || code != 0 || tok == "" {
		return "cannot decrypt " + credFile + " (wrong user, TPM2 unavailable or name mismatch)"
	}
	return opWhoamiVerdict(ctx, []string{opServiceAccountEnv + "=" + tok})
}

// unitLoadsCredential reports whether the installed unit has a
// LoadCredentialEncrypted line for the named credential, and its file.
func unitLoadsCredential(unitPath, name string) (string, bool) {
	f, err := os.Open(unitPath)
	if err != nil {
		return "", false
	}
	defer f.Close() //nolint:errcheck // read-only
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "LoadCredentialEncrypted="+name+":"); ok {
			return v, true
		}
	}
	return "", false
}
