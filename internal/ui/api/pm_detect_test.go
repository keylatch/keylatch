package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/keylatch/keylatch/internal/ui/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPMDetectHandler_MethodNotAllowed verifies non-GET is rejected.
func TestPMDetectHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()
	h := &api.PMDetectHandler{}
	req := httptest.NewRequest(http.MethodPost, "/api/password-managers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// TestPMDetectHandler_OnlyOpFound verifies correct JSON when only op is in PATH.
func TestPMDetectHandler_OnlyOpFound(t *testing.T) {
	// Do not run in parallel — modifies PATH via Setenv.
	dir := t.TempDir()
	opBin := filepath.Join(dir, "op")
	require.NoError(t, os.WriteFile(opBin, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	// Inject a fresh detect function that reads the temp PATH directly.
	detect := func() api.PmAvailability {
		origPath := os.Getenv("PATH")
		defer func() { _ = os.Setenv("PATH", origPath) }()
		_ = os.Setenv("PATH", dir)

		_, opErr := lookPath(dir, "op")
		_, awsErr := lookPath(dir, "aws")
		_, vaultErr := lookPath(dir, "vault")
		return api.PmAvailability{
			Op:         opErr == nil,
			AwsSM:      awsErr == nil,
			HashiVault: vaultErr == nil,
		}
	}

	h := &api.PMDetectHandler{}
	h.SetDetect(detect)

	req := httptest.NewRequest(http.MethodGet, "/api/password-managers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]bool
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.True(t, body["op"], "op should be true when binary exists in PATH")
	assert.False(t, body["aws_sm"], "aws_sm should be false when binary absent")
	assert.False(t, body["hashivault"], "hashivault should be false when binary absent")
}

// TestPMDetectHandler_AllKeysPresent verifies the response always contains all
// three required keys regardless of availability.
func TestPMDetectHandler_AllKeysPresent(t *testing.T) {
	t.Parallel()

	h := &api.PMDetectHandler{}
	h.SetDetect(func() api.PmAvailability {
		return api.PmAvailability{Op: false, AwsSM: false, HashiVault: false}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/password-managers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]bool
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))

	for _, key := range []string{"op", "aws_sm", "hashivault"} {
		_, ok := body[key]
		assert.True(t, ok, "key %q must be present in response", key)
	}
}

// TestPMDetectHandler_AllAvailable verifies the response when all three CLIs are
// available.
func TestPMDetectHandler_AllAvailable(t *testing.T) {
	t.Parallel()

	h := &api.PMDetectHandler{}
	h.SetDetect(func() api.PmAvailability {
		return api.PmAvailability{Op: true, AwsSM: true, HashiVault: true}
	})

	req := httptest.NewRequest(http.MethodGet, "/api/password-managers", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var body map[string]bool
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.True(t, body["op"])
	assert.True(t, body["aws_sm"])
	assert.True(t, body["hashivault"])
}

// lookPath checks whether a binary exists in the given dir (not os exec.LookPath
// to avoid depending on the real PATH, which varies by test environment).
func lookPath(dir, name string) (string, error) {
	full := filepath.Join(dir, name)
	_, err := os.Stat(full)
	if err != nil {
		return "", err
	}
	return full, nil
}
