package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsProviderRefURI(t *testing.T) {
	for _, v := range []string{"op://v/i/f", "aws-sm://eu-west-1/s", "hashivault://secret/x"} {
		assert.True(t, store.IsProviderRefURI([]byte(v)), v)
	}
	for _, v := range []string{"", "plain-value", "OP://v/i", "https://example.invalid", " op://v/i"} {
		assert.False(t, store.IsProviderRefURI([]byte(v)), v)
	}
}

func TestValidateProviderRefURI(t *testing.T) {
	valid := []string{"op://vault/item", "op://vault/item/field", " aws-sm://us-east-1/name ", "hashivault://secret/app#key"}
	for _, u := range valid {
		assert.NoError(t, store.ValidateProviderRefURI(u), u)
	}
	invalid := map[string]string{
		"":                  "empty URI",
		"vault/item":        "no scheme",
		"://vault/item":     "empty scheme",
		"s3://bucket/key":   "unsupported scheme",
		"op://vaultonly":    "must be op://",
		"aws-sm://region/":  "must be aws-sm://",
		"hashivault://path": "must be hashivault://",
	}
	for u, want := range invalid {
		err := store.ValidateProviderRefURI(u)
		require.Error(t, err, u)
		assert.ErrorIs(t, err, store.ErrInvalidURI, u)
		assert.Contains(t, err.Error(), want, u)
	}
}

func TestResolver_StderrIsClassifiedNotEchoed(t *testing.T) {
	sessionLeak := "session=" + strings.Repeat("z", 24)
	cases := []struct {
		scheme, bin, ref, stderr, hint string
	}{
		{"op", "/fake/op", "op://v/i/f", "[ERROR] item not found " + sessionLeak, "item or field not found"},
		{"op", "/fake/op", "op://v/i/f", "401 Unauthorized " + sessionLeak, "authentication error"},
		{"op", "/fake/op", "op://v/i/f", "you are not signed in " + sessionLeak, "not signed in"},
		{"op", "/fake/op", "op://v/i/f", "weird " + sessionLeak, "op CLI error"},
		{"aws-sm", "/fake/aws", "aws-sm://eu-west-1/s", "ResourceNotFoundException " + sessionLeak, "secret not found"},
		{"aws-sm", "/fake/aws", "aws-sm://eu-west-1/s", "AccessDenied " + sessionLeak, "access denied"},
		{"aws-sm", "/fake/aws", "aws-sm://eu-west-1/s", "Unable to locate credentials " + sessionLeak, "no AWS credentials"},
		{"aws-sm", "/fake/aws", "aws-sm://eu-west-1/s", "boom " + sessionLeak, "aws CLI error"},
		{"hashivault", "/fake/vault", "hashivault://secret/app", "No secret exists at secret/app " + sessionLeak, "path not found"},
		{"hashivault", "/fake/vault", "hashivault://secret/app#x", "No value found at secret/app for field x " + sessionLeak, "field not found in secret"},
		{"hashivault", "/fake/vault", "hashivault://secret/app", "Code: 403 " + sessionLeak, "permission denied"},
		{"hashivault", "/fake/vault", "hashivault://secret/app", "dial tcp: lookup vault: server misbehaving " + sessionLeak, "cannot reach Vault server"},
		{"hashivault", "/fake/vault", "hashivault://secret/app", "something odd " + sessionLeak, "vault CLI error"},
	}
	for _, tc := range cases {
		r := &mockRunner{stderr: []byte(tc.stderr), exitCode: 2}
		res := store.NewResolver(r).WithBinOverride(tc.scheme, tc.bin)
		_, err := res.Resolve(context.Background(), tc.ref)
		require.Error(t, err, tc.stderr)
		assert.Contains(t, err.Error(), tc.hint, tc.stderr)
		assert.NotContains(t, err.Error(), sessionLeak, "raw stderr must never be surfaced")
	}
}

func TestResolver_RunnerErrorsAreWrapped(t *testing.T) {
	cause := errors.New("exec failed")
	for scheme, ref := range map[string]string{"op": "op://v/i/f", "aws-sm": "aws-sm://r/s", "hashivault": "hashivault://secret/app"} {
		res := store.NewResolver(&mockRunner{err: cause}).WithBinOverride(scheme, "/fake/bin")
		_, err := res.Resolve(context.Background(), ref)
		assert.ErrorIs(t, err, cause, scheme)
		assert.Contains(t, err.Error(), "runner error", scheme)
	}
}

func TestResolver_HashiVaultInputValidation(t *testing.T) {
	r := &mockRunner{stdout: []byte("value\n")}
	res := store.NewResolver(r).WithBinOverride("hashivault", "/fake/vault")
	for ref, want := range map[string]string{
		"hashivault://":                 "empty KV path",
		"hashivault://secret/a;rm -rf":  "invalid KV path",
		"hashivault://secret/app#bad$f": "invalid field name",
		"hashivault://secret/app#%zz":   "invalid URI",
	} {
		_, err := res.Resolve(context.Background(), ref)
		require.Error(t, err, ref)
		assert.Contains(t, err.Error(), want, ref)
	}
	_, ok := r.lastCall()
	assert.False(t, ok, "invalid input must be rejected before invoking the CLI")

	empty := store.NewResolver(&mockRunner{stdout: []byte("\n")}).WithBinOverride("hashivault", "/fake/vault")
	_, err := empty.Resolve(context.Background(), "hashivault://secret/app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty output")
}

func TestResolver_AWSSMEdgeCases(t *testing.T) {
	res := store.NewResolver(&mockRunner{stdout: []byte("not-json\n")}).WithBinOverride("aws-sm", "/fake/aws")
	_, err := res.Resolve(context.Background(), "aws-sm://eu-west-1/s#key")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not JSON")

	res = store.NewResolver(&mockRunner{stdout: []byte(`{"n":42}`)}).WithBinOverride("aws-sm", "/fake/aws")
	v, err := res.Resolve(context.Background(), "aws-sm://eu-west-1/s#n")
	require.NoError(t, err)
	assert.Equal(t, "42", string(v), "non-string JSON values are returned raw")

	_, err = res.Resolve(context.Background(), "aws-sm:///secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be non-empty")
}

func TestResolver_BinaryLookupOnPATH(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, ref := range []string{"op://v/i/f", "aws-sm://r/s", "hashivault://secret/app"} {
		_, err := store.NewResolver(&mockRunner{}).Resolve(context.Background(), ref)
		assert.ErrorIs(t, err, store.ErrBinaryNotFound, ref)
	}
}
