package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
	"github.com/keylatch/keylatch/internal/proxy"
	"github.com/keylatch/keylatch/internal/registry"
	"github.com/keylatch/keylatch/internal/runtime"
)

// gatewayProxyMode is the KEYLATCH_RUNTIME value injected into the child env.
const gatewayProxyMode = string(runtime.RuntimeGatewayProxy)

// ProxyServerStarter is the interface the proxy driver uses to start the
// gateway_proxy server. This allows tests to inject a stub.
type ProxyServerStarter interface {
	// Addr returns the address the proxy is listening on.
	Addr() string
	// CACertPath returns the path to the CA certificate on disk.
	// Empty if no CA is configured.
	CACertPath() string
}

// proxyDriver starts the gateway_proxy server, mints a scoped session token,
// injects the proxy env vars into the child environment, and execs the subprocess.
// Provider API keys are NEVER present in the child environment (S9-15).
type proxyDriver struct {
	server     *proxy.Server
	signingKey []byte
	storePath  string
	caPath     string
}

// NewProxyDriver returns a Driver that routes child subprocess traffic through
// the gateway_proxy server s. signingKey (32 bytes) and storePath are used to
// mint a scoped Keylatch session token.
//
// Key lifecycle: the caller owns signingKey and is responsible for zeroing it
// after the driver is no longer needed. The driver retains a reference to the
// slice but does NOT zero it — zeroing in Run would corrupt the shared backing
// array and break any subsequent Run calls (W1).
func NewProxyDriver(s *proxy.Server, signingKey []byte, storePath, caPath string) Driver {
	return &proxyDriver{
		server:     s,
		signingKey: signingKey,
		storePath:  storePath,
		caPath:     caPath,
	}
}

// Run implements Driver for proxyDriver.
//
// Steps:
//  1. Ensure proxy server is running (if proxy.Server.Addr is set).
//  2. Mint a scoped Keylatch session token for this capability.
//  3. Call proxy.EnvInject to build child env with proxy addr, token, CA path.
//     Provider API keys MUST be absent from the child env.
//  4. Launch subprocess with child env.
//  5. Return RuntimeReceipt.
func (d *proxyDriver) Run(ctx context.Context, req ExecRequest, _ registry.ConnectionTemplate) (RuntimeReceipt, error) {
	receipt := RuntimeReceipt{
		Runtime:         gatewayProxyMode,
		CredentialShape: string(runtime.DeliveryKeylatchSessionToken),
	}

	if len(req.Command) == 0 {
		return receipt, fmt.Errorf("gateway_proxy: empty command")
	}

	// Step 2: mint a scoped session token.
	actor := req.Actor
	if actor == "" {
		actor = "proxy_driver"
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}

	capability := req.Capability
	if capability == "" {
		capability = req.ConnectionSlug + ".inject"
	}

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: []string{capability},
		TTL:          ttl,
		LLMSession:   false, // proxy mode is always non-LLM (CLI-invoked)
		SigningKey:   d.signingKey,
		StorePath:    d.storePath,
	})
	if err != nil {
		return receipt, fmt.Errorf("gateway_proxy: mint session token: %w", err)
	}

	// Step 3: build child env with proxy vars injected.
	// Start from a minimal base env (not os.Environ()) to ensure provider API
	// keys do not leak into the child process (S9-15).
	// We add only essential PATH and minimal runtime vars.
	// T-08-02: --extra vars are appended on top of the minimal base even when
	// CleanEnv is not set, because the proxy driver is always minimally clean.
	baseEnv := proxyBaseEnv()
	for _, k := range req.ExtraEnvVars {
		if v := os.Getenv(k); v != "" {
			baseEnv = append(baseEnv, k+"="+v)
		}
	}
	addr := ""
	if d.server != nil && d.server.Addr != "" {
		addr = d.server.Addr
	} else {
		// Default proxy addr.
		addr = "127.0.0.1:7879"
	}

	childEnv := proxy.EnvInject(baseEnv, addr, jwtStr, d.caPath)

	// Step 4: launch subprocess.
	stdout := req.Stdout
	if stdout == nil {
		stdout = os.Stdout
	}
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	//nolint:gosec // G204: command allowlist enforcement is caller-side (DispatchRunner.Run).
	cmd := exec.CommandContext(ctx, req.Command[0], req.Command[1:]...)
	cmd.Env = childEnv
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if req.Stdin != nil {
		cmd.Stdin = req.Stdin
	} else {
		cmd.Stdin = os.Stdin
	}
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	}

	runErr := cmd.Run()

	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			receipt.ExitCode = exitErr.ExitCode()
			return receipt, nil
		}
		return receipt, fmt.Errorf("gateway_proxy: exec: %w", runErr)
	}
	return receipt, nil
}

// proxyBaseEnv returns the minimal base environment for the proxy child process.
// Does NOT include os.Environ() to ensure provider credentials cannot leak.
func proxyBaseEnv() []string {
	// Include only PATH and HOME so common tools are findable.
	var env []string
	for _, key := range []string{"PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL", "TMPDIR", "TMP", "TEMP"} {
		if v := os.Getenv(key); v != "" {
			env = append(env, key+"="+v)
		}
	}
	return env
}
