// Package gcpsm implements the Backend interface using GCP Secret Manager.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - runner.OK is checked before returning plaintext.
package gcpsm

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*GCPSecretManagerBackend)(nil)

// SecretManagerClient is the interface satisfied by the real GCP client and by test mocks.
type SecretManagerClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
	DeleteSecret(ctx context.Context, req *secretmanagerpb.DeleteSecretRequest, opts ...gax.CallOption) error
	ListSecrets(ctx context.Context, req *secretmanagerpb.ListSecretsRequest, opts ...gax.CallOption) *secretmanager.SecretIterator
	Close() error
}

// Options configures a GCPSecretManagerBackend.
type Options struct {
	ProjectID       string
	CredentialsFile string // path to SA JSON; empty = ADC

	// ClientOptions allows injecting custom client options (used in tests).
	ClientOptions []option.ClientOption

	// Client allows injecting a mock client for tests.
	Client SecretManagerClient
}

// GCPSecretManagerBackend implements backend.Backend using GCP Secret Manager.
type GCPSecretManagerBackend struct {
	projectID string
	client    SecretManagerClient
}

// Open creates and configures a GCPSecretManagerBackend.
func Open(ctx context.Context, opts Options) (*GCPSecretManagerBackend, error) {
	if opts.ProjectID == "" {
		return nil, fmt.Errorf("gcp-sm backend: project_id is required")
	}

	if opts.Client != nil {
		return &GCPSecretManagerBackend{
			projectID: opts.ProjectID,
			client:    opts.Client,
		}, nil
	}

	var clientOpts []option.ClientOption
	if opts.CredentialsFile != "" {
		// Use WithAuthCredentialsFile with explicit ServiceAccount type to avoid
		// the security risk flagged by the deprecated WithCredentialsFile (SA1019).
		// CredentialsFile is operator-supplied and expected to be a service account JSON.
		clientOpts = append(clientOpts, option.WithAuthCredentialsFile(option.ServiceAccount, opts.CredentialsFile))
	}
	clientOpts = append(clientOpts, opts.ClientOptions...)

	client, err := secretmanager.NewClient(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("gcp-sm backend: create client: %w", err)
	}

	return &GCPSecretManagerBackend{
		projectID: opts.ProjectID,
		client:    client,
	}, nil
}

// Name implements backend.Backend.
func (b *GCPSecretManagerBackend) Name() string { return "gcp-sm" }

// Capabilities implements backend.Backend.
func (b *GCPSecretManagerBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *GCPSecretManagerBackend) ID() string {
	return fmt.Sprintf("gcp-sm:%s", b.projectID)
}

// secretParent returns the GCP parent resource path for the project.
func (b *GCPSecretManagerBackend) secretParent() string {
	return fmt.Sprintf("projects/%s", b.projectID)
}

// secretName returns the full GCP secret resource name.
func (b *GCPSecretManagerBackend) secretName(name string) string {
	return fmt.Sprintf("projects/%s/secrets/%s", b.projectID, name)
}

// versionName returns the full GCP secret version resource name.
func (b *GCPSecretManagerBackend) versionName(name string) string {
	return fmt.Sprintf("projects/%s/secrets/%s/versions/latest", b.projectID, name)
}

// Get retrieves the latest version of a secret from GCP Secret Manager.
func (b *GCPSecretManagerBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	result, err := b.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: b.versionName(path),
	})
	if err != nil {
		if isGCPNotFound(err) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return nil, backend.Meta{}, fmt.Errorf("gcp-sm Get %q: %w", path, err)
	}

	if result.Payload == nil {
		return nil, backend.Meta{}, fmt.Errorf("%w: %s (nil payload)", backend.ErrNotFound, path)
	}

	m := backend.Meta{
		Path:    path,
		Backend: "gcp-sm",
		Version: 1,
	}
	return result.Payload.Data, m, nil
}

// Set creates or updates a secret in GCP Secret Manager.
func (b *GCPSecretManagerBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	// Try adding a version to an existing secret first.
	_, err := b.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
		Parent:  b.secretName(path),
		Payload: &secretmanagerpb.SecretPayload{Data: value},
	})
	if err == nil {
		return nil
	}

	// If not found, create the secret then add a version.
	if isGCPNotFound(err) {
		_, createErr := b.client.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   b.secretParent(),
			SecretId: path,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{
					Replication: &secretmanagerpb.Replication_Automatic_{
						Automatic: &secretmanagerpb.Replication_Automatic{},
					},
				},
			},
		})
		if createErr != nil {
			return fmt.Errorf("gcp-sm Set %q (create): %w", path, createErr)
		}
		_, addErr := b.client.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{
			Parent:  b.secretName(path),
			Payload: &secretmanagerpb.SecretPayload{Data: value},
		})
		if addErr != nil {
			return fmt.Errorf("gcp-sm Set %q (add version): %w", path, addErr)
		}
		return nil
	}

	return fmt.Errorf("gcp-sm Set %q: %w", path, err)
}

// Delete removes a secret from GCP Secret Manager.
func (b *GCPSecretManagerBackend) Delete(ctx context.Context, path string) error {
	err := b.client.DeleteSecret(ctx, &secretmanagerpb.DeleteSecretRequest{
		Name: b.secretName(path),
	})
	if err != nil {
		if isGCPNotFound(err) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return fmt.Errorf("gcp-sm Delete %q: %w", path, err)
	}
	return nil
}

// List returns metadata-only entries from GCP Secret Manager.
func (b *GCPSecretManagerBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	it := b.client.ListSecrets(ctx, &secretmanagerpb.ListSecretsRequest{
		Parent: b.secretParent(),
	})

	var entries []backend.Entry
	for {
		secret, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gcp-sm List: %w", err)
		}
		// Extract short name from full resource name.
		name := secretShortName(secret.Name)
		if prefix != "" && !strings.HasPrefix(name, prefix) {
			continue
		}
		entries = append(entries, backend.Entry{
			Meta: backend.Meta{
				Path:    name,
				Backend: "gcp-sm",
				Version: 1,
			},
			Exists: true,
		})
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *GCPSecretManagerBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *GCPSecretManagerBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *GCPSecretManagerBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *GCPSecretManagerBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *GCPSecretManagerBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *GCPSecretManagerBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close releases the GCP client connection.
func (b *GCPSecretManagerBackend) Close() error {
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// isGCPNotFound returns true when a GCP API error indicates the secret does not exist.
func isGCPNotFound(err error) bool {
	if err == nil {
		return false
	}
	if s, ok := status.FromError(err); ok {
		return s.Code() == codes.NotFound
	}
	return false
}

// secretShortName extracts the short name from a full resource name like
// "projects/proj/secrets/mysecret".
func secretShortName(fullName string) string {
	parts := strings.Split(fullName, "/")
	if len(parts) >= 4 {
		return parts[len(parts)-1]
	}
	return fullName
}
