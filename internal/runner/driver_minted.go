package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// mintedMode is the KEYLATCH_RUNTIME value injected into the child env.
const mintedMode = string(runtime.RuntimeMinted)

// ErrUnsupportedRuntime is returned when a template does not have the
// required runtime support configuration for the requested driver.
var ErrUnsupportedRuntime = errors.New("runner: template does not support this runtime mode")

// MintedCredential is a credential minted for one run. Close wipes it and
// revokes it with the provider.
type MintedCredential interface {
	Value(ctx context.Context, field string) ([]byte, error)
	Close()
}

// MintOpenRequest identifies the connection a credential is minted for.
type MintOpenRequest struct {
	Connection string
	Namespace  string
	Caller     callerkind.Kind
}

// MintOpener checks the connection's mint policy and returns a credential
// that mints on first use. It writes the audit event of each mint.
type MintOpener func(ctx context.Context, tmpl registry.ConnectionTemplate, req MintOpenRequest) (MintedCredential, error)

type mintedDriver struct{ open MintOpener }

// NewMintedDriver returns the driver for the minted runtime. The child gets a
// credential minted from the template's mint strategy and nothing from the
// parent environment beyond the clean-env allowlist; the stored root
// credential is never read, so a template with only static fields cannot run
// here.
func NewMintedDriver(open MintOpener) Driver { return &mintedDriver{open: open} }

func (d *mintedDriver) Run(ctx context.Context, req ExecRequest, tmpl registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Runtime:         mintedMode,
		CredentialShape: string(runtime.DeliveryProviderEphemeral),
	}
	if len(req.Command) == 0 {
		return receipt, errors.New("minted: empty command")
	}
	if !supportsMinted(tmpl) {
		return receipt, fmt.Errorf("%w: %s has no mint strategy", ErrUnsupportedRuntime, tmpl.Provider)
	}

	namespace := req.Namespace
	if namespace == "" {
		namespace = "default"
	}
	cred, err := d.open(ctx, tmpl, MintOpenRequest{Connection: req.ConnectionSlug, Namespace: namespace, Caller: req.Caller})
	if err != nil {
		return receipt, fmt.Errorf("minted: %w", err)
	}
	defer cred.Close()

	// The allowlist applies whether or not --clean-env was given: a minted
	// credential is the only secret the command may hold.
	env := runtime.CleanBaseEnv(os.Environ(), req.ExtraEnvVars...)
	var secrets [][]byte
	defer func() {
		for _, s := range secrets {
			clear(s)
		}
	}()
	for _, rule := range tmpl.InjectionRules {
		if !tmpl.IsMinted(rule.Source) {
			continue
		}
		v, err := cred.Value(ctx, rule.Source)
		if err != nil {
			return receipt, fmt.Errorf("minted: %w", err)
		}
		secrets = append(secrets, v)
		env = appendOrReplace(env, rule.EnvVar, string(v))
	}
	if len(secrets) == 0 {
		return receipt, fmt.Errorf("%w: %s injects no minted field", ErrUnsupportedRuntime, tmpl.Provider)
	}
	env = append(env, "KEYLATCH_RUNTIME="+mintedMode)
	env = mergeEnvPairs(env, req.LocalEnv)

	stdout, stderr := req.Stdout, req.Stderr
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	//nolint:gosec // G204: command allowlist enforcement is caller-side (DispatchRunner.Run).
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	cmd.Env = env
	guard := newOutputGuard(stdout, stderr, req.WorkingDir, req.FileScan, secrets...)
	cmd.Stdout = guard.Stdout()
	cmd.Stderr = guard.Stderr()
	cmd.Stdin = req.Stdin
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	cmd.Dir = req.WorkingDir

	runErr := cmd.Run()
	receipt.LeakedFiles = guard.Finish()
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			receipt.ExitCode = exitErr.ExitCode()
			return receipt, nil
		}
		return receipt, fmt.Errorf("minted: exec: %w", runErr)
	}
	return receipt, nil
}

// supportsMinted reports whether the template lists the minted runtime and
// has a field that Keylatch mints.
func supportsMinted(tmpl registry.ConnectionTemplate) bool {
	listed := tmpl.RuntimeSupport.Preferred == registry.RuntimeMinted ||
		slices.Contains(tmpl.RuntimeSupport.Supported, registry.RuntimeMinted)
	return listed && len(tmpl.MintedFields) > 0
}
