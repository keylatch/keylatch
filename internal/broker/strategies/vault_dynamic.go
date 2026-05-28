package strategies

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
)

// VaultDynamicSecretStrategy calls a HashiCorp Vault dynamic-secret endpoint.
// TTL is bound to the Vault lease ID. When the cache entry is evicted, the
// lease is revoked via the Vault lease-revocation endpoint.
type VaultDynamicSecretStrategy struct {
	provider      string
	vaultAddr     string
	secretPath    string
	getVaultToken func(namespace string) ([]byte, error)
	httpClient    *http.Client
}

// NewVaultDynamicSecretStrategy creates the strategy.
func NewVaultDynamicSecretStrategy(
	vaultAddr, secretPath string,
	getVaultToken func(namespace string) ([]byte, error),
) *VaultDynamicSecretStrategy {
	return &VaultDynamicSecretStrategy{
		provider:      "hashicorp-vault",
		vaultAddr:     vaultAddr,
		secretPath:    secretPath,
		getVaultToken: getVaultToken,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Provider returns "hashicorp-vault".
func (s *VaultDynamicSecretStrategy) Provider() string { return s.provider }

// Exchange calls the Vault dynamic-secret endpoint and returns a credential.
// The credential is encoded as JSON in tokenBytes with the lease_id included
// so that callers can revoke it on eviction.
func (s *VaultDynamicSecretStrategy) Exchange(ctx context.Context, _, _, namespace string) (broker.ExchangeResult, error) {
	vaultToken, err := s.getVaultToken(namespace)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: get vault token: %w", err)
	}
	defer zeroBytes(vaultToken)

	endpoint := s.vaultAddr + "/v1/" + s.secretPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", string(vaultToken))

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: read response: %w", err)
	}

	var payload struct {
		LeaseID       string         `json:"lease_id"`
		LeaseDuration int            `json:"lease_duration"`
		Data          map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: parse response: %w", err)
	}

	ttl := time.Duration(payload.LeaseDuration) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}

	// Store the credential data + lease_id as a JSON blob in tokenBytes.
	tokenData := map[string]any{
		"lease_id": payload.LeaseID,
		"data":     payload.Data,
	}
	tokenBytes, err := json.Marshal(tokenData)
	if err != nil {
		return broker.ExchangeResult{}, fmt.Errorf("vault_dynamic: marshal token data: %w", err)
	}

	result := broker.NewExchangeResult(s.provider, "", ttl, broker.FreshExchange, tokenBytes)
	zeroBytes(tokenBytes)
	return result, nil
}

// RevokeLease revokes a Vault lease ID.
func (s *VaultDynamicSecretStrategy) RevokeLease(ctx context.Context, leaseID string, vaultToken []byte) error {
	endpoint := s.vaultAddr + "/v1/sys/leases/revoke"
	payload := fmt.Sprintf(`{"lease_id":%q}`, leaseID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, jsonReader(payload))
	if err != nil {
		return fmt.Errorf("vault_dynamic: revoke build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", string(vaultToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault_dynamic: revoke http request: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault_dynamic: revoke returned %d", resp.StatusCode)
	}
	return nil
}

type stringReader struct {
	s   string
	off int
}

func (r *stringReader) Read(p []byte) (n int, err error) {
	if r.off >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.off:])
	r.off += n
	return
}

func jsonReader(s string) io.Reader { return &stringReader{s: s} }
