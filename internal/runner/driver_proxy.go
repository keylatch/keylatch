package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
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
// Provider API keys are NEVER present in the child environment.
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

	// Mint a scoped JWT for audit/revocation tracking (gateway token store).
	// This is independent of the proxy's own caller-auth bearer token (the
	// proxy caller-auth check, below): the JWT records who/what was authorized to run this capability;
	// the caller-auth token is what the child must present back to the proxy
	// listener to prove it is the process we intended to authorize.
	if _, _, err := token.Mint(token.TokenSpec{
		Actor:        actor,
		Capabilities: []string{capability},
		TTL:          ttl,
		LLMSession:   false, // proxy mode is always non-LLM (CLI-invoked)
		SigningKey:   d.signingKey,
		StorePath:    d.storePath,
	}); err != nil {
		return receipt, fmt.Errorf("gateway_proxy: mint session token: %w", err)
	}

	// The value injected into the child's KEYLATCH_SESSION_TOKEN env var
	// is the proxy's own per-session caller-auth bearer token — this is what
	// the child must present as "Proxy-Authorization: Bearer <token>" on
	// every request to the proxy listener. Without this, any same-user
	// process could reach 127.0.0.1:7879 and drive credential injection.
	var authToken string
	if d.server != nil {
		var tokenErr error
		authToken, tokenErr = d.server.EnsureToken()
		if tokenErr != nil {
			return receipt, fmt.Errorf("gateway_proxy: mint caller-auth token: %w", tokenErr)
		}
	}

	// Step 3: build child env with proxy vars injected.
	// Start from a minimal base env (not os.Environ()) to ensure provider API
	// keys do not leak into the child process.
	// We add only essential PATH and minimal runtime vars.
	// --extra vars are appended on top of the minimal base even when
	// CleanEnv is not set, because the proxy driver is always minimally clean.
	//
	// docker-server-security hardening: --extra is an operator/CLI-controlled
	// list of env var NAMES to copy from the parent process into the child.
	// Without a denylist, an operator could pass --extra OPENAI_API_KEY (or
	// any other provider credential var) and silently defeat this invariant — the
	// exact leak this minimal base env exists to prevent. providerKeyDenylist
	// blocks any --extra name that matches a well-known provider credential
	// env var, regardless of what value is currently set for it.
	// Resolve stderr early (normally done in Step 4 below) so the denylist
	// warning below can be written to the caller-supplied stream.
	stderr := req.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}

	baseEnv := proxyBaseEnv()
	for _, k := range req.ExtraEnvVars {
		if isCredentialShapedName(k) {
			// Never let --extra leak a credential-shaped var into the
			// gateway_proxy child env — tell the operator so the omission
			// isn't silently confusing.
			fmt.Fprintf(stderr, "warning: --extra %q looks like a credential env var; withheld from gateway_proxy child env\n", k)
			continue
		}
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

	childEnv := proxy.EnvInject(baseEnv, addr, authToken, d.caPath)

	// Step 4: launch subprocess. stderr was already resolved above (needed
	// for the --extra denylist warning before this point).
	stdout := req.Stdout
	if stdout == nil {
		stdout = os.Stdout
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

// providerKeyDenylist lists well-known provider credential env var names that
// --extra (req.ExtraEnvVars) must never be allowed to copy from the parent
// process into a gateway_proxy child, no matter what the operator requests.
//
// This mirrors the env var names in internal/allow's envVarRules (kept as a
// local, duplicated list rather than an import: internal/allow is read-only
// for this change per file-ownership constraints, and its exported surface —
// Suggest() — is a heuristic "which provider is likely configured" helper,
// not a name-only lookup table suitable for a security denylist. If
// internal/allow later exposes the raw name list, this should be
// consolidated to avoid drift between the two.
var providerKeyDenylist = map[string]bool{
	"OPENAI_API_KEY":            true,
	"ANTHROPIC_API_KEY":         true,
	"GITHUB_TOKEN":              true,
	"STRIPE_SECRET_KEY":         true,
	"SLACK_BOT_TOKEN":           true,
	"OPENROUTER_API_KEY":        true,
	"GOOGLE_API_KEY":            true,
	"AZURE_OPENAI_API_KEY":      true,
	"COHERE_API_KEY":            true,
	"MISTRAL_API_KEY":           true,
	"GEMINI_API_KEY":            true,
	"HUGGINGFACE_TOKEN":         true,
	"REPLICATE_API_TOKEN":       true,
	"ELEVENLABS_API_KEY":        true,
	"CLOUDFLARE_API_TOKEN":      true,
	"SUPABASE_SERVICE_ROLE_KEY": true,
	"TURSO_AUTH_TOKEN":          true,
	"PINECONE_API_KEY":          true,
	"WEAVIATE_API_KEY":          true,
	"RESEND_API_KEY":            true,
	"SENDGRID_API_KEY":          true,
}

// credentialWords are uppercased trailing words that mark an --extra var name
// as credential-shaped, on top of the exact-name providerKeyDenylist above.
//
// docker-server-security hardening: providerKeyDenylist only covers ~20
// well-known provider names — any other secret-shaped var (AWS_SECRET_ACCESS_KEY,
// AWS_SESSION_TOKEN, NPM_TOKEN, a custom *_SECRET, etc.) would otherwise pass
// straight through os.Getenv(k) into the gateway_proxy child, defeating this guarantee
// for anything not on the fixed list.
//
// Matched as a SUFFIX of the uppercased name, so both glued compounds
// (APIKEY, DBPASSWORD) and separated names (OPENAI_API_KEY, MY_TOKEN) are
// caught, while a middle match like FOO_TOKEN_BAR is not over-blocked. A
// pathological benign name that happens to end in one of these words (e.g.
// MONKEY -> KEY, or SPIN -> PIN) is withheld too; that is the safe direction
// for a security denylist and the caller is warned by name, so it stays a
// denylist (not a strict allowlist) and ordinary vars (PATH, LANG, NODE_ENV,
// MY_APP_REGION, AWS_REGION, ...) are never blocked.
var credentialWords = []string{
	"KEY",
	"TOKEN",
	"SECRET",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
	"CREDENTIALS",
	"PIN",
}

// isCredentialShapedName reports whether name looks like it holds a secret —
// either an exact match against providerKeyDenylist, or its uppercased form
// ending in one of credentialWords. Used to deny --extra names on the
// gateway_proxy path, where the child must never receive raw secrets.
func isCredentialShapedName(name string) bool {
	if providerKeyDenylist[name] {
		return true
	}
	upper := strings.ToUpper(name)
	for _, w := range credentialWords {
		if strings.HasSuffix(upper, w) {
			return true
		}
	}
	return false
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
