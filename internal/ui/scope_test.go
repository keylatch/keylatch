package ui_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultScope_LLMSession(t *testing.T) {
	t.Parallel()
	s := ui.DefaultScope(true)
	assert.Equal(t, ui.ScopeStatusOnly, s, "LLM session must always get ScopeStatusOnly")
}

func TestDefaultScope_NoLLM(t *testing.T) {
	t.Parallel()
	s := ui.DefaultScope(false)
	assert.Equal(t, ui.ScopeAdmin, s)
}

func TestScopeFilter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		have ui.UISessionScope
		need ui.UISessionScope
		ok   bool
	}{
		{ui.ScopeAdmin, ui.ScopeAdmin, true},
		{ui.ScopeAdmin, ui.ScopeSetup, true},
		{ui.ScopeAdmin, ui.ScopeStatusOnly, true},
		{ui.ScopeSetup, ui.ScopeAdmin, false},
		{ui.ScopeStatusOnly, ui.ScopeAdmin, false},
		{ui.ScopeTokenMinting, ui.ScopeAdmin, true},
		{ui.ScopeTokenMinting, ui.ScopeTokenMinting, true},
		{ui.ScopeAdmin, ui.ScopeTokenMinting, false},
	}
	for _, tc := range cases {
		got := ui.ScopeFilter(tc.have, tc.need)
		assert.Equal(t, tc.ok, got, "ScopeFilter(%v, %v)", tc.have, tc.need)
	}
}

func TestScopeString(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "status-only", ui.ScopeStatusOnly.String())
	assert.Equal(t, "setup", ui.ScopeSetup.String())
	assert.Equal(t, "admin", ui.ScopeAdmin.String())
	assert.Equal(t, "token-minting", ui.ScopeTokenMinting.String())
}

func TestParseScope(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in  string
		out ui.UISessionScope
		err bool
	}{
		{"status-only", ui.ScopeStatusOnly, false},
		{"setup", ui.ScopeSetup, false},
		{"admin", ui.ScopeAdmin, false},
		{"token-minting", ui.ScopeTokenMinting, false},
		{"invalid", ui.ScopeStatusOnly, true},
	}
	for _, tc := range cases {
		got, err := ui.ParseScope(tc.in)
		if tc.err {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
			assert.Equal(t, tc.out, got)
		}
	}
}
