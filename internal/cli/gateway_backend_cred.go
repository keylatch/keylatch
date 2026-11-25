package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	kexec "github.com/keylatch/keylatch/internal/exec"
)

// backendCredentialEnv is every environment variable a keylatch backend reads
// a secret from; only these can be filled from a sealed credential, so the flag
// cannot be used to inject arbitrary variables (LD_PRELOAD, PATH, ...).
var backendCredentialEnv = []string{
	"OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "KEYLATCH_OP_CONNECT_TOKEN",
	"BW_SESSION",
	"VAULT_TOKEN", "KEYLATCH_VAULT_TOKEN", "KEYLATCH_VAULT_SECRET_ID",
	"AWS_SECRET_ACCESS_KEY", "KEYLATCH_AWS_SECRET_ACCESS_KEY",
	"AZURE_CLIENT_SECRET", "KEYLATCH_AZURE_CLIENT_SECRET",
	"KEYLATCH_GCP_CREDENTIALS_JSON",
	"DOPPLER_TOKEN", "KEYLATCH_DOPPLER_TOKEN",
	"INFISICAL_CLIENT_SECRET", "KEYLATCH_INFISICAL_CLIENT_SECRET",
}

var credentialNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

// backendCredential maps a systemd credential name to the variable it fills.
type backendCredential struct{ Name, Env string }

// parseBackendCredentials parses repeated <cred-name>=<ENV_VAR> values.
func parseBackendCredentials(values []string) ([]backendCredential, error) {
	var out []backendCredential
	for _, v := range values {
		name, env, ok := strings.Cut(v, "=")
		if !ok || !credentialNameRE.MatchString(name) {
			return nil, fmt.Errorf("--backend-credential %q: use <cred-name>=<ENV_VAR> (name: letters, digits, '.', '_', '-')", v)
		}
		if name == systemdCredentialKEK {
			return nil, fmt.Errorf("--backend-credential %q: the name %q is reserved for the vault key", v, systemdCredentialKEK)
		}
		if !slices.Contains(backendCredentialEnv, env) {
			return nil, fmt.Errorf("--backend-credential %q: %s is not a variable a backend reads a secret from (allowed: %s)", v, env, strings.Join(backendCredentialEnv, ", "))
		}
		for _, o := range out {
			if o.Name == name || o.Env == env {
				return nil, fmt.Errorf("--backend-credential %q repeats a credential name or variable", v)
			}
		}
		out = append(out, backendCredential{name, env})
	}
	return out, nil
}

func (c backendCredential) flag() string { return c.Name + "=" + c.Env }

// opSARunner runs systemd-creds and op; tests substitute a fake.
var opSARunner kexec.CommandRunner = kexec.DefaultRunner

var resolveBinFunc = kexec.Resolve

// exportBackendCredentials reads each credential from $CREDENTIALS_DIRECTORY
// and exports it into this process's environment (and so the backend
// processes it starts). Values are never logged, written to an env file or put
// on a command line.
func exportBackendCredentials(creds []backendCredential) error {
	for _, c := range creds {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" && runtime.GOOS == "darwin" {
			tok, err := keychainSecret(c.Name)
			if err != nil {
				return fmt.Errorf("--backend-credential %s: %w", c.flag(), err)
			}
			if err := os.Setenv(c.Env, tok); err != nil {
				return err
			}
			continue
		}
		if dir == "" {
			return fmt.Errorf("--backend-credential %s: CREDENTIALS_DIRECTORY is not set; run this under the service manager (systemd: LoadCredentialEncrypted=%s:<file>)", c.flag(), c.Name)
		}
		data, err := os.ReadFile(filepath.Join(dir, c.Name))
		if err != nil {
			return fmt.Errorf("--backend-credential %s: credential not readable: %w", c.flag(), err)
		}
		tok := strings.TrimSpace(string(data))
		clear(data)
		if tok == "" {
			return fmt.Errorf("--backend-credential %s: credential is empty", c.flag())
		}
		if err := os.Setenv(c.Env, tok); err != nil {
			return err
		}
	}
	return nil
}

// backendVerdict is a one-line, token-free status for a credential already in
// the environment (or extraEnv). Only the 1Password service account has a
// live check (`op whoami`); other backends get a decrypt-only verdict.
func backendVerdict(ctx context.Context, envVar string, extraEnv []string) string {
	if envVar != "OP_SERVICE_ACCOUNT_TOKEN" {
		return envVar + " is present (no live check for this backend)"
	}
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

// checkSealedBackendCredential decrypts one sealed credential for this call
// only and returns the verdict. The value is never printed.
func checkSealedBackendCredential(ctx context.Context, c backendCredential, credFile string) string {
	bin := resolveBinFunc("systemd-creds")
	if bin == "" {
		return "systemd-creds not found; cannot decrypt the credential here"
	}
	out, _, code, err := opSARunner.Run(ctx, bin, []string{"decrypt", "--user", "--name=" + c.Name, credFile, "-"}, nil)
	defer clear(out)
	tok := strings.TrimSpace(string(out))
	if err != nil || code != 0 || tok == "" {
		return "cannot decrypt " + credFile + " (wrong user, TPM2 unavailable or name mismatch)"
	}
	return backendVerdict(ctx, c.Env, []string{c.Env + "=" + tok})
}

// unitBackendCredentials returns the installed unit's backend credentials with
// their sealed files: ExecStart's --backend-credential flags joined with the
// LoadCredentialEncrypted lines.
func unitBackendCredentials(unitPath string) (creds []backendCredential, files map[string]string) {
	f, err := os.Open(unitPath)
	if err != nil {
		return nil, nil
	}
	defer f.Close() //nolint:errcheck // read-only
	files = map[string]string{}
	var flags []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "LoadCredentialEncrypted="); ok {
			if name, file, ok := strings.Cut(v, ":"); ok {
				files[name] = file
			}
		}
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			fields := strings.Fields(v)
			for i, fl := range fields {
				if fl == "--backend-credential" && i+1 < len(fields) {
					flags = append(flags, fields[i+1])
				}
			}
		}
	}
	creds, _ = parseBackendCredentials(flags)
	return creds, files
}

// keychainSecret reads the secret stored for a backend credential in the login
// Keychain: service "keylatch-backend", account <name>.
func keychainSecret(name string) (string, error) {
	bin := resolveBinFunc("security")
	if bin == "" {
		return "", errors.New("the security tool was not found")
	}
	out, _, code, err := opSARunner.Run(context.Background(), bin, []string{"find-generic-password", "-s", keychainBackendService, "-a", name, "-w"}, nil)
	defer clear(out)
	tok := strings.TrimSpace(string(out))
	if err != nil || code != 0 || tok == "" {
		return "", fmt.Errorf("no Keychain item (service %q, account %q); add it with: security add-generic-password -s %s -a %s -w", keychainBackendService, name, keychainBackendService, name)
	}
	return tok, nil
}

const keychainBackendService = "keylatch-backend"
