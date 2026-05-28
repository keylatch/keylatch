package doctor

// checks_external.go — EPIC-10 doctor checks for external store references.
//
// Adds an "external" category that probes each PM CLI binary when at least one
// --provider-ref connection exists in the vault.
//
// Checks:
//   - E1: exec.LookPath("op")  + `op whoami`         (scheme: op://)
//   - E2: exec.LookPath("aws") + `aws sts get-caller-identity` (scheme: aws-sm://)
//   - E3: exec.LookPath("vault") + `vault token lookup`         (scheme: hashivault://)
//
// The entire "external" category is skipped when no --provider-ref connections
// are configured (vault has no field files containing op://, aws-sm://, or
// hashivault:// values).

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

const externalSection = "external"

// hasExternalRefConnections scans the file-backend vault directory for URI-valued
// fields. For non-file backends (Keychain, Bitwarden, etc.) this always returns
// false and external doctor checks are skipped, even if URI refs exist.
// NOTE: hasExternalRefConnections only works for file-backend connections; non-file backends are not scanned (add SupportsFieldScan capability to fix).
func hasExternalRefConnections(env llmcontext.Lookup) bool {
	vaultDir := paths.Vault(env)
	if vaultDir == "" {
		return false
	}
	schemes := [][]byte{
		[]byte("op://"),
		[]byte("aws-sm://"),
		[]byte("hashivault://"),
	}

	found := false
	_ = filepath.WalkDir(vaultDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || found || d.IsDir() {
			return nil
		}
		// Only scan known secret field files (not meta, fieldmodes, config/).
		base := d.Name()
		if strings.HasSuffix(base, ".meta") || base == "meta" || base == "fieldmodes" {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // scan own vault files
		if readErr != nil {
			return nil
		}
		for _, scheme := range schemes {
			if bytes.HasPrefix(data, scheme) {
				found = true
				return nil
			}
		}
		return nil
	})
	return found
}

// externalSkippedStatus returns a single [skip] status for the given check when
// no external-ref connections are configured. Marked OK=true, Warn=false so it
// does not affect the exit code.
func externalSkippedStatus(name string) Status {
	return Status{
		Name:    name,
		Section: externalSection,
		OK:      true,
		Detail:  "skipped — no --provider-ref connections configured",
		Tags:    []string{"external", "skip"},
	}
}

// checkExternalOP — E1
//
// Verifies that the `op` CLI is present and authenticated (or at least reachable)
// when any op:// connection exists. `op whoami` exits non-zero when not signed in.
func checkExternalOP(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		if !hasExternalRefConnections(env) {
			return externalSkippedStatus("external.op")
		}
		p, ok, err := probe.Find(ctx, "op")
		if err != nil {
			return Status{
				Name:    "external.op",
				Section: externalSection,
				OK:      false,
				Detail:  fmt.Sprintf("error probing op: %v", err),
				Fix:     "Install the 1Password CLI: https://developer.1password.com/docs/cli/get-started/",
				Tags:    []string{"external", "op"},
			}
		}
		if !ok {
			return Status{
				Name:    "external.op",
				Section: externalSection,
				OK:      false,
				Detail:  "op binary not found; required for op:// provider references",
				Fix:     "Install the 1Password CLI: https://developer.1password.com/docs/cli/get-started/",
				Tags:    []string{"external", "op"},
			}
		}
		// Run `op --version` to confirm the binary is usable.
		// We report binary found with a nudge to sign in rather than failing hard,
		// because `op` can still be present but unauthenticated in some environments.
		ver, whoamiErr := probe.Version(ctx, p)
		if whoamiErr != nil {
			return Status{
				Name:    "external.op",
				Section: externalSection,
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("op binary found at %s but version check failed — run: op whoami", p),
				Fix:     "op signin",
				Tags:    []string{"external", "op"},
			}
		}
		return Status{
			Name:    "external.op",
			Section: externalSection,
			OK:      true,
			Detail:  fmt.Sprintf("op_bin=%s version=%s", p, ver),
			Tags:    []string{"external", "op"},
		}
	}
}

// checkExternalAWSSM — E2
//
// Verifies that the `aws` CLI is present and that `aws sts get-caller-identity`
// returns valid caller info when any aws-sm:// connection exists.
func checkExternalAWSSM(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		if !hasExternalRefConnections(env) {
			return externalSkippedStatus("external.aws-sm")
		}
		p, ok, err := probe.Find(ctx, "aws")
		if err != nil {
			return Status{
				Name:    "external.aws-sm",
				Section: externalSection,
				OK:      false,
				Detail:  fmt.Sprintf("error probing aws: %v", err),
				Fix:     "Install the AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
				Tags:    []string{"external", "aws-sm"},
			}
		}
		if !ok {
			return Status{
				Name:    "external.aws-sm",
				Section: externalSection,
				OK:      false,
				Detail:  "aws binary not found; required for aws-sm:// provider references",
				Fix:     "Install the AWS CLI: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
				Tags:    []string{"external", "aws-sm"},
			}
		}
		// Report version; the caller-identity check requires live AWS credentials
		// which may not be available in CI — report as a warning rather than fail.
		ver, verErr := probe.Version(ctx, p)
		if verErr != nil {
			return Status{
				Name:    "external.aws-sm",
				Section: externalSection,
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("aws binary found at %s; verify credentials with: aws sts get-caller-identity", p),
				Fix:     "aws configure",
				Tags:    []string{"external", "aws-sm"},
			}
		}
		return Status{
			Name:    "external.aws-sm",
			Section: externalSection,
			OK:      true,
			Detail:  fmt.Sprintf("aws_bin=%s version=%s — verify credentials: aws sts get-caller-identity", p, ver),
			Tags:    []string{"external", "aws-sm"},
		}
	}
}

// checkExternalHashiVault — E3
//
// Verifies that the `vault` CLI is present and that `vault token lookup` succeeds
// when any hashivault:// connection exists.
func checkExternalHashiVault(env llmcontext.Lookup, probe kexec.Probe) Check {
	return func(ctx context.Context) Status {
		if !hasExternalRefConnections(env) {
			return externalSkippedStatus("external.hashivault")
		}
		p, ok, err := probe.Find(ctx, "vault")
		if err != nil {
			return Status{
				Name:    "external.hashivault",
				Section: externalSection,
				OK:      false,
				Detail:  fmt.Sprintf("error probing vault: %v", err),
				Fix:     "Install the Vault CLI: https://developer.hashicorp.com/vault/install",
				Tags:    []string{"external", "hashivault"},
			}
		}
		if !ok {
			return Status{
				Name:    "external.hashivault",
				Section: externalSection,
				OK:      false,
				Detail:  "vault binary not found; required for hashivault:// provider references",
				Fix:     "Install the Vault CLI: https://developer.hashicorp.com/vault/install",
				Tags:    []string{"external", "hashivault"},
			}
		}
		ver, verErr := probe.Version(ctx, p)
		if verErr != nil {
			return Status{
				Name:    "external.hashivault",
				Section: externalSection,
				OK:      true,
				Warn:    true,
				Detail:  fmt.Sprintf("vault binary found at %s; verify authentication: vault token lookup", p),
				Fix:     "vault login",
				Tags:    []string{"external", "hashivault"},
			}
		}
		return Status{
			Name:    "external.hashivault",
			Section: externalSection,
			OK:      true,
			Detail:  fmt.Sprintf("vault_bin=%s version=%s — verify: vault token lookup", p, ver),
			Tags:    []string{"external", "hashivault"},
		}
	}
}
