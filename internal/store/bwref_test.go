package store

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseBWRef(t *testing.T) {
	t.Parallel()
	ref, err := ParseBWRef("Acme%20Corp/Team%2FProd/My%20Item/field:password")
	require.NoError(t, err)
	assert.Equal(t, BWRef{Scope: "Acme Corp", Collection: "Team/Prod", Item: "My Item", Field: "field:password"}, ref)
	assert.Equal(t, "password", ref.CustomFieldName())
	assert.Equal(t, "bw://Acme%20Corp/Team%2FProd/My%20Item/field:password", ref.String())
}

func TestParseBWRef_RoundTripWildcardAndLiteralDash(t *testing.T) {
	t.Parallel()
	ref, err := ParseBWRef("personal/-/item/password")
	require.NoError(t, err)
	assert.Equal(t, BWAny, ref.Collection)
	assert.Equal(t, "bw://personal/-/item/password", ref.String())

	ref, err = ParseBWRef("personal/%2D/item/password")
	require.NoError(t, err)
	assert.Equal(t, "-", ref.Collection)
}

func TestParseBWRef_Invalid(t *testing.T) {
	t.Parallel()
	for _, rest := range []string{
		"personal/-/item", "personal/-/item/password/extra", "personal//item/password",
		"personal/-/item/%zz", "personal/-/item/totp", "personal/-/item/TOTP", "personal/-/item/field:", "personal/-/it%00em/password",
	} {
		_, err := ParseBWRef(rest)
		assert.Error(t, err, rest)
		assert.True(t, errors.Is(ValidateProviderRefURI("bw://"+rest), ErrInvalidURI), rest)
	}
}

func TestValidateProviderRefURI_BW(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateProviderRefURI("bw://personal/-/My%20Item/password"))
	assert.True(t, IsProviderRefURI([]byte("bw://personal/-/x/password")))
}
