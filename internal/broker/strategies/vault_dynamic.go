package strategies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// MaxVaultLease is the longest lease MintScoped accepts.
const MaxVaultLease = time.Hour

// ErrVaultLeaseMismatch is returned when Vault issued a lease that is missing
// or longer than the one requested. The lease has already been revoked, or
// revocation was attempted, when this error is returned.
var ErrVaultLeaseMismatch = errors.New("vault_dynamic: issued lease does not match the requested scope")

// VaultScope bounds one dynamic secret.
type VaultScope struct {
	// MaxLease is the longest lease accepted; it defaults to and may not
	// exceed MaxVaultLease.
	MaxLease time.Duration
}

// VaultLease is one dynamic secret and the lease that governs it.
type VaultLease struct {
	LeaseID string
	Data    map[string]any
	Expires time.Time
}

// Zero drops the secret data.
func (l *VaultLease) Zero() { *l = VaultLease{} }

// VaultDynamicSecretStrategy reads a HashiCorp Vault dynamic-secret path and
// revokes the lease when the run ends.
type VaultDynamicSecretStrategy struct {
	vaultAddr     string
	secretPath    string
	getVaultToken func(namespace string) ([]byte, error)
	httpClient    *http.Client
	now           func() time.Time
}

// NewVaultDynamicSecretStrategy creates the strategy.
func NewVaultDynamicSecretStrategy(
	vaultAddr, secretPath string,
	getVaultToken func(namespace string) ([]byte, error),
) *VaultDynamicSecretStrategy {
	return &VaultDynamicSecretStrategy{
		vaultAddr:     strings.TrimRight(vaultAddr, "/"),
		secretPath:    strings.TrimPrefix(secretPath, "/"),
		getVaultToken: getVaultToken,
		httpClient:    &http.Client{Timeout: 15 * time.Second},
		now:           time.Now,
	}
}

// Provider returns "hashicorp-vault".
func (s *VaultDynamicSecretStrategy) Provider() string { return "hashicorp-vault" }

// MintScoped reads a new dynamic secret. A reply with no lease, or a lease
// longer than scope.MaxLease, is revoked and refused: the secret would
// outlive the run it was minted for.
func (s *VaultDynamicSecretStrategy) MintScoped(ctx context.Context, namespace string, scope VaultScope) (VaultLease, error) {
	if scope.MaxLease == 0 {
		scope.MaxLease = MaxVaultLease
	}
	if scope.MaxLease < 0 || scope.MaxLease > MaxVaultLease {
		return VaultLease{}, fmt.Errorf("vault_dynamic: the lease limit must be between 1 second and %s", MaxVaultLease)
	}
	vaultToken, err := s.getVaultToken(namespace)
	if err != nil {
		return VaultLease{}, fmt.Errorf("vault_dynamic: get vault token: %w", err)
	}
	defer clear(vaultToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.vaultAddr+"/v1/"+s.secretPath, nil)
	if err != nil {
		return VaultLease{}, fmt.Errorf("vault_dynamic: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", string(vaultToken))
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return VaultLease{}, fmt.Errorf("vault_dynamic: http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return VaultLease{}, fmt.Errorf("vault_dynamic: server returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return VaultLease{}, fmt.Errorf("vault_dynamic: read response: %w", err)
	}
	var payload struct {
		LeaseID       string         `json:"lease_id"`
		LeaseDuration int            `json:"lease_duration"`
		Data          map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return VaultLease{}, fmt.Errorf("vault_dynamic: parse response: %w", err)
	}

	lease := time.Duration(payload.LeaseDuration) * time.Second
	switch {
	case payload.LeaseID == "":
		return VaultLease{}, fmt.Errorf("%w: the secret has no lease, so it cannot be revoked", ErrVaultLeaseMismatch)
	case lease <= 0 || lease > scope.MaxLease:
		if rerr := s.revoke(ctx, payload.LeaseID, vaultToken); rerr != nil {
			return VaultLease{}, fmt.Errorf("%w: lease of %s exceeds %s, and revoking it failed: %v", ErrVaultLeaseMismatch, lease, scope.MaxLease, rerr)
		}
		return VaultLease{}, fmt.Errorf("%w: lease of %s exceeds %s; it was revoked", ErrVaultLeaseMismatch, lease, scope.MaxLease)
	}
	return VaultLease{LeaseID: payload.LeaseID, Data: payload.Data, Expires: s.now().Add(lease)}, nil
}

// Revoke ends the lease.
func (s *VaultDynamicSecretStrategy) Revoke(ctx context.Context, namespace, leaseID string) error {
	vaultToken, err := s.getVaultToken(namespace)
	if err != nil {
		return fmt.Errorf("vault_dynamic: get vault token: %w", err)
	}
	defer clear(vaultToken)
	return s.revoke(ctx, leaseID, vaultToken)
}

func (s *VaultDynamicSecretStrategy) revoke(ctx context.Context, leaseID string, vaultToken []byte) error {
	payload, err := json.Marshal(map[string]string{"lease_id": leaseID})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, s.vaultAddr+"/v1/sys/leases/revoke", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("vault_dynamic: revoke build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", string(vaultToken))
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault_dynamic: revoke http request: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault_dynamic: revoke returned %d", resp.StatusCode)
	}
	return nil
}
