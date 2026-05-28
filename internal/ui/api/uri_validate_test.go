package api_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateRefURI_ValidCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		uri  string
	}{
		{"op with full path", "op://Personal/OpenRouter/api_key"},
		{"op minimal", "op://vault/item"},
		{"aws-sm with region and secret", "aws-sm://us-east-1/my-secret-id"},
		{"aws-sm with JSON key fragment", "aws-sm://eu-west-1/myapp#api_key"},
		{"hashivault with path", "hashivault://secret/myapp/config"},
		{"hashivault with field fragment", "hashivault://secret/myapp/config#api_key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := api.ValidateRefURI("field", tc.uri)
			assert.Nil(t, err, "expected valid URI %q to pass", tc.uri)
		})
	}
}

func TestValidateRefURI_InvalidCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		uri   string
		field string
	}{
		{"empty URI", "", "api_key"},
		{"op no path", "op://", "api_key"},
		{"aws-sm no path", "aws-sm://", "api_key"},
		{"hashivault no path", "hashivault://", "api_key"},
		{"unknown scheme", "doppler://some/path", "api_key"},
		{"no scheme", "not-a-uri", "api_key"},
		{"partial scheme", "op:/", "api_key"},
		{"op single segment no slash", "op://ab", "api_key"},
		{"blank whitespace", "   ", "api_key"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := api.ValidateRefURI(tc.field, tc.uri)
			require.NotNil(t, err, "expected invalid URI %q to fail", tc.uri)
			assert.Equal(t, tc.field, err.Field, "field name should match")
			assert.NotEmpty(t, err.Message)
		})
	}
}
