// Package awssm implements the Backend interface using AWS Secrets Manager.
//
// Security invariants:
//   - Never log plaintext secret values; use HMAC of path for audit.
//   - runner.OK is checked before returning plaintext.
package awssm

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/runner"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

// compile-time interface check.
var _ backend.Backend = (*AWSSecretsManagerBackend)(nil)

// Options configures an AWSSecretsManagerBackend.
type Options struct {
	Region      string
	AccessKey   string
	SecretKey   string
	ForceDelete bool

	// SMClient allows injecting a mock client for tests.
	SMClient SecretsManagerClient
}

// SecretsManagerClient is the interface satisfied by the AWS SDK client and by test mocks.
type SecretsManagerClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	ListSecrets(ctx context.Context, params *secretsmanager.ListSecretsInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.ListSecretsOutput, error)
	CreateSecret(ctx context.Context, params *secretsmanager.CreateSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.CreateSecretOutput, error)
	PutSecretValue(ctx context.Context, params *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
	DeleteSecret(ctx context.Context, params *secretsmanager.DeleteSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DeleteSecretOutput, error)
	DescribeSecret(ctx context.Context, params *secretsmanager.DescribeSecretInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.DescribeSecretOutput, error)
}

// AWSSecretsManagerBackend implements backend.Backend using AWS Secrets Manager.
type AWSSecretsManagerBackend struct {
	region string
	force  bool
	client SecretsManagerClient
}

// Open creates and configures an AWSSecretsManagerBackend.
// If opts.SMClient is set it is used directly (for tests). Otherwise the real
// AWS SDK client is constructed from the provided credentials or the default
// credential chain.
func Open(ctx context.Context, opts Options) (*AWSSecretsManagerBackend, error) {
	b := &AWSSecretsManagerBackend{
		region: opts.Region,
		force:  opts.ForceDelete,
		client: opts.SMClient,
	}
	if b.client != nil {
		return b, nil
	}

	var cfgOpts []func(*awsconfig.LoadOptions) error
	if opts.Region != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithRegion(opts.Region))
	}
	if opts.AccessKey != "" && opts.SecretKey != "" {
		cfgOpts = append(cfgOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(opts.AccessKey, opts.SecretKey, ""),
		))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, cfgOpts...)
	if err != nil {
		return nil, fmt.Errorf("aws-sm backend: load config: %w", err)
	}

	b.client = secretsmanager.NewFromConfig(cfg)
	return b, nil
}

// Name implements backend.Backend.
func (b *AWSSecretsManagerBackend) Name() string { return "aws-sm" }

// Capabilities implements backend.Backend.
func (b *AWSSecretsManagerBackend) Capabilities() []backend.Capability {
	return []backend.Capability{
		backend.CapList,
		backend.CapNetworkedFetch,
	}
}

// ID returns a stable unique identifier for this backend instance.
func (b *AWSSecretsManagerBackend) ID() string {
	return fmt.Sprintf("aws-sm:%s", b.region)
}

// Get retrieves a secret value from AWS Secrets Manager.
func (b *AWSSecretsManagerBackend) Get(ctx context.Context, path string) ([]byte, backend.Meta, error) {
	if !runner.OK(ctx) {
		return nil, backend.Meta{}, backend.ErrLocked
	}

	out, err := b.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(path),
	})
	if err != nil {
		if isAWSNotFound(err) {
			return nil, backend.Meta{}, fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return nil, backend.Meta{}, fmt.Errorf("aws-sm Get %q: %w", path, err)
	}

	var val []byte
	switch {
	case out.SecretString != nil:
		val = []byte(*out.SecretString)
	case out.SecretBinary != nil:
		val = out.SecretBinary
	default:
		return nil, backend.Meta{}, fmt.Errorf("%w: %s (no value)", backend.ErrNotFound, path)
	}

	m := backend.Meta{
		Path:    path,
		Backend: "aws-sm",
		Version: 1,
	}
	if out.ARN != nil {
		m.Accessor = backend.ID(*out.ARN)
	}
	return val, m, nil
}

// Set creates or updates a secret in AWS Secrets Manager.
func (b *AWSSecretsManagerBackend) Set(ctx context.Context, path string, value []byte, _ backend.Meta) error {
	strVal := string(value)
	// Check if secret exists.
	_, err := b.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(path),
	})
	if err != nil {
		if isAWSNotFound(err) {
			// Create new secret.
			_, createErr := b.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
				Name:         aws.String(path),
				SecretString: aws.String(strVal),
			})
			if createErr != nil {
				return fmt.Errorf("aws-sm Set %q (create): %w", path, createErr)
			}
			return nil
		}
		return fmt.Errorf("aws-sm Set %q (describe): %w", path, err)
	}

	// Update existing secret.
	_, err = b.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(path),
		SecretString: aws.String(strVal),
	})
	if err != nil {
		return fmt.Errorf("aws-sm Set %q (put): %w", path, err)
	}
	return nil
}

// Delete removes a secret from AWS Secrets Manager.
func (b *AWSSecretsManagerBackend) Delete(ctx context.Context, path string) error {
	_, err := b.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:                   aws.String(path),
		ForceDeleteWithoutRecovery: aws.Bool(b.force),
	})
	if err != nil {
		if isAWSNotFound(err) {
			return fmt.Errorf("%w: %s", backend.ErrNotFound, path)
		}
		return fmt.Errorf("aws-sm Delete %q: %w", path, err)
	}
	return nil
}

// List returns metadata-only entries (names) from AWS Secrets Manager.
func (b *AWSSecretsManagerBackend) List(ctx context.Context, prefix string) ([]backend.Entry, error) {
	var entries []backend.Entry
	paginator := secretsmanager.NewListSecretsPaginator(b.client, &secretsmanager.ListSecretsInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("aws-sm List: %w", err)
		}
		for _, s := range page.SecretList {
			if s.Name == nil {
				continue
			}
			name := *s.Name
			if prefix != "" && !strings.HasPrefix(name, prefix) {
				continue
			}
			m := backend.Meta{
				Path:    name,
				Backend: "aws-sm",
				Version: 1,
			}
			if s.ARN != nil {
				m.Accessor = backend.ID(*s.ARN)
			}
			entries = append(entries, backend.Entry{Meta: m, Exists: true})
		}
	}
	return entries, nil
}

// GetMeta is not supported by this backend.
func (b *AWSSecretsManagerBackend) GetMeta(_ context.Context, _ string) (vmeta.Meta, error) {
	return vmeta.Meta{}, backend.ErrNotSupported
}

// SetMeta is not supported by this backend.
func (b *AWSSecretsManagerBackend) SetMeta(_ context.Context, _ string, _ vmeta.Meta) error {
	return backend.ErrNotSupported
}

// ListMeta is not supported by this backend.
func (b *AWSSecretsManagerBackend) ListMeta(_ context.Context, _ string) ([]vmeta.Meta, error) {
	return nil, backend.ErrNotSupported
}

// GetVersioned is not supported by this backend.
func (b *AWSSecretsManagerBackend) GetVersioned(_ context.Context, _ string, _ int) ([]byte, error) {
	return nil, backend.ErrNotSupported
}

// SetVersioned is not supported by this backend.
func (b *AWSSecretsManagerBackend) SetVersioned(_ context.Context, _ string, _ int, _ []byte) error {
	return backend.ErrNotSupported
}

// DeleteVersioned is not supported by this backend.
func (b *AWSSecretsManagerBackend) DeleteVersioned(_ context.Context, _ string, _ int) error {
	return backend.ErrNotSupported
}

// Close is a no-op for the aws-sm backend.
func (b *AWSSecretsManagerBackend) Close() error { return nil }

// isAWSNotFound returns true when an AWS error indicates the secret does not exist.
func isAWSNotFound(err error) bool {
	if err == nil {
		return false
	}
	var nfe *types.ResourceNotFoundException
	return errors.As(err, &nfe)
}
