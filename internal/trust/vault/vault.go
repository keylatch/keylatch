package vault

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/trust"
)

// Adapter implements trust.RootOfTrust using HashiCorp Vault / OpenBao Transit.
type Adapter struct {
	opts       Options
	id         string
	httpClient *http.Client
	hasMTLS    bool
}

// New creates a new Vault Transit adapter.
func New(opts Options) (*Adapter, error) {
	if opts.Addr == "" {
		return nil, fmt.Errorf("%w: vault addr not set", trust.ErrRootUnavailable)
	}
	client, err := newHTTPClient(opts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", trust.ErrRootUnavailable, err)
	}
	hasMTLS := opts.ClientCert != "" && opts.ClientKey != ""
	return &Adapter{
		opts:       opts,
		id:         "vault:" + opts.TransitKeyName,
		httpClient: client,
		hasMTLS:    hasMTLS,
	}, nil
}

func (a *Adapter) ID() string           { return a.id }
func (a *Adapter) Type() trust.RootType { return trust.RootVaultTransit }

func (a *Adapter) Has(c trust.Capability) bool {
	switch c {
	case trust.CapWrap, trust.CapSignChallenge, trust.CapAttestation:
		return true
	case trust.CapMTLSClientAuth:
		return a.hasMTLS
	case trust.CapLaunchdSafe:
		// Safe when using mTLS or AppRole (non-interactive).
		return a.hasMTLS || a.opts.AuthMethod == "approle" || a.opts.AuthMethod == "k8s"
	case trust.CapUserPresence, trust.CapHardwareBound:
		return false
	default:
		return false
	}
}

// Wrap encrypts dek using Vault Transit encrypt. Zeros dek before returning.
func (a *Adapter) Wrap(ctx context.Context, dek []byte) ([]byte, error) {
	defer zeroBytes(dek)

	token, err := a.getToken(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroString(&token)

	// Base64-encode the DEK for Vault's API.
	b64 := base64.StdEncoding.EncodeToString(dek)
	body := fmt.Sprintf(`{"plaintext":%q}`, b64)

	url := fmt.Sprintf("%s/v1/transit/encrypt/%s", a.opts.Addr, a.opts.TransitKeyName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vault: wrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: transit encrypt: %v", trust.ErrRootUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("vault: transit encrypt failed (status %d): %s", resp.StatusCode, sanitize(body))
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("vault: read encrypt response: %w", err)
	}

	ciphertext := jsonExtractString(rawBody, "ciphertext")
	if ciphertext == "" {
		return nil, fmt.Errorf("vault: no ciphertext in encrypt response")
	}
	return []byte(ciphertext), nil
}

// Unwrap decrypts a wrapped DEK using Vault Transit decrypt.
func (a *Adapter) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	token, err := a.getToken(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroString(&token)

	body := fmt.Sprintf(`{"ciphertext":%q}`, string(wrapped))
	url := fmt.Sprintf("%s/v1/transit/decrypt/%s", a.opts.Addr, a.opts.TransitKeyName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vault: unwrap request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: transit decrypt: %v", trust.ErrRootUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("vault: transit decrypt failed (status %d): %s", resp.StatusCode, sanitize(b))
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("vault: read decrypt response: %w", err)
	}

	b64Plaintext := jsonExtractString(rawBody, "plaintext")
	if b64Plaintext == "" {
		return nil, fmt.Errorf("vault: no plaintext in decrypt response")
	}

	dek, err := base64.StdEncoding.DecodeString(b64Plaintext)
	if err != nil {
		return nil, fmt.Errorf("vault: decode plaintext: %w", err)
	}
	return dek, nil
}

// Sign uses Vault Transit sign with Ed25519 to sign challenge.
func (a *Adapter) Sign(ctx context.Context, challenge []byte) ([]byte, crypto.PublicKey, error) {
	token, err := a.getToken(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer zeroString(&token)

	b64Input := base64.StdEncoding.EncodeToString(challenge)
	body := fmt.Sprintf(`{"input":%q}`, b64Input)

	url := fmt.Sprintf("%s/v1/transit/sign/%s", a.opts.Addr, a.opts.TransitKeyName)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("vault: sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: transit sign: %v", trust.ErrRootUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, nil, fmt.Errorf("vault: transit sign failed (status %d): %s", resp.StatusCode, sanitize(b))
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, nil, fmt.Errorf("vault: read sign response: %w", err)
	}

	sigStr := jsonExtractString(rawBody, "signature")
	if sigStr == "" {
		return nil, nil, fmt.Errorf("vault: no signature in sign response")
	}

	return []byte(sigStr), nil, nil
}

func (a *Adapter) Verify(_ context.Context, _, _ []byte, _ crypto.PublicKey) error {
	return fmt.Errorf("%w: vault transit verify not implemented", trust.ErrCapabilityUnsupported)
}

func (a *Adapter) RequirePresence(_ context.Context, _ string) (trust.PresenceProof, error) {
	// Vault does not require physical presence; return ErrCapabilityUnsupported.
	return trust.PresenceProof{}, trust.ErrCapabilityUnsupported
}

func (a *Adapter) VerifyPresenceProof(_ context.Context, _ trust.PresenceProof) error {
	return trust.ErrCapabilityUnsupported
}

func (a *Adapter) Attest(_ context.Context) (trust.Attestation, error) {
	return trust.Attestation{Format: "vault-token"}, nil
}

// Close revokes the current token (best-effort) and releases resources.
func (a *Adapter) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	token, err := a.getToken(ctx)
	if err != nil {
		return nil // best-effort; ignore auth errors on close
	}
	defer zeroString(&token)
	_ = a.revokeToken(ctx, token)
	return nil
}

func (a *Adapter) revokeToken(ctx context.Context, token string) error {
	url := a.opts.Addr + "/v1/auth/token/revoke-self"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}
	addVaultHeaders(req, a.opts.Namespace, token)
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (a *Adapter) getToken(ctx context.Context) (string, error) {
	return authenticate(ctx, a.opts, a.httpClient)
}

// --- KV backend interface ---

// Get reads a key from Vault KV v2.
func (a *Adapter) Get(ctx context.Context, key string) ([]byte, error) {
	token, err := a.getToken(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroString(&token)

	url := fmt.Sprintf("%s/v1/secret/data/%s", a.opts.Addr, key)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: get request: %w", err)
	}
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: kv get: %v", trust.ErrRootUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("vault: key not found")
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("vault: kv get failed (status %d): %s", resp.StatusCode, sanitize(b))
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("vault: read kv response: %w", err)
	}
	return rawBody, nil
}

// Set writes a value to Vault KV v2.
func (a *Adapter) Set(ctx context.Context, key string, value []byte) error {
	token, err := a.getToken(ctx)
	if err != nil {
		return err
	}
	defer zeroString(&token)

	payload := map[string]any{"data": map[string]any{"value": base64.StdEncoding.EncodeToString(value)}}
	b, _ := json.Marshal(payload)

	url := fmt.Sprintf("%s/v1/secret/data/%s", a.opts.Addr, key)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(b)))
	if err != nil {
		return fmt.Errorf("vault: set request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: kv set: %v", trust.ErrRootUnavailable, err)
	}
	resp.Body.Close()
	return nil
}

// Delete removes a key from Vault KV v2.
func (a *Adapter) Delete(ctx context.Context, key string) error {
	token, err := a.getToken(ctx)
	if err != nil {
		return err
	}
	defer zeroString(&token)

	url := fmt.Sprintf("%s/v1/secret/metadata/%s", a.opts.Addr, key)
	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("vault: delete request: %w", err)
	}
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: kv delete: %v", trust.ErrRootUnavailable, err)
	}
	resp.Body.Close()
	return nil
}

// List lists keys under a prefix in Vault KV v2.
func (a *Adapter) List(ctx context.Context, prefix string) ([]string, error) {
	token, err := a.getToken(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroString(&token)

	url := fmt.Sprintf("%s/v1/secret/metadata/%s?list=true", a.opts.Addr, prefix)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("vault: list request: %w", err)
	}
	addVaultHeaders(req, a.opts.Namespace, token)

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: kv list: %v", trust.ErrRootUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	rawBody, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("vault: read list response: %w", err)
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rawBody, &result); err != nil {
		return nil, fmt.Errorf("vault: parse list response: %w", err)
	}
	return result.Data.Keys, nil
}

// zeroBytes zeroes a byte slice in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// zeroString zeroes a string's backing memory (best-effort via reflection).
func zeroString(s *string) {
	*s = ""
}

func init() {
	trust.Register(trust.RootVaultTransit, func(spec trust.RootSpec) (trust.RootOfTrust, error) {
		addr := ""
		authMethod := ""
		transitKey := ""
		namespace := ""
		if spec.Extra != nil {
			if v, ok := spec.Extra["addr"].(string); ok {
				addr = v
			}
			if v, ok := spec.Extra["auth_method"].(string); ok {
				authMethod = v
			}
			if v, ok := spec.Extra["transit_key"].(string); ok {
				transitKey = v
			}
			if v, ok := spec.Extra["namespace"].(string); ok {
				namespace = v
			}
		}
		return New(Options{
			Addr:           addr,
			AuthMethod:     authMethod,
			TransitKeyName: transitKey,
			Namespace:      namespace,
			Label:          spec.Label,
		})
	})
}
