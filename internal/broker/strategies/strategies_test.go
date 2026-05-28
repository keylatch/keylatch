package strategies_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/broker"
	"github.com/keylatch/keylatch/internal/broker/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- StaticGatewayOnlyStrategy ----

func TestStaticGatewayOnly_HappyPath(t *testing.T) {
	const token = "static-token-value"
	s := strategies.NewStaticGatewayOnlyStrategy("myprovider", func(_ string) ([]byte, error) {
		return []byte(token), nil
	})

	assert.Equal(t, "myprovider", s.Provider())

	res, err := s.Exchange(context.Background(), "actor", "session", "default")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestStaticGatewayOnly_GetTokenError(t *testing.T) {
	s := strategies.NewStaticGatewayOnlyStrategy("myprovider", func(_ string) ([]byte, error) {
		return nil, errors.New("keychain locked")
	})

	_, err := s.Exchange(context.Background(), "actor", "session", "default")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get token")
}

func TestStaticGatewayOnly_BlockedInDirectBrokeredNamespace(t *testing.T) {
	s := strategies.NewStaticGatewayOnlyStrategy("myprovider", func(_ string) ([]byte, error) {
		return []byte("tok"), nil
	})

	_, err := s.Exchange(context.Background(), "actor", "session", "direct_brokered:ns1")
	require.Error(t, err)
	assert.ErrorIs(t, err, broker.ErrUnsupportedExchange)
}

func TestStaticGatewayOnly_TokenNotInExchangeMetadata(t *testing.T) {
	const secret = "sk-static-secret-do-not-log"
	s := strategies.NewStaticGatewayOnlyStrategy("myprovider", func(_ string) ([]byte, error) {
		return []byte(secret), nil
	})

	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	// The string representation of the result (which callers may log) must
	// not contain the raw secret.
	resStr := fmt.Sprintf("%+v", res)
	assert.NotContains(t, resStr, secret, "token must not appear in result metadata")
}

// ---- OAuthRefreshStrategy ----

func TestOAuthRefresh_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))
		assert.Equal(t, "my-refresh-tok", r.FormValue("refresh_token"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-access-token",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "client-id", "client-secret",
		func(_, _ string) ([]byte, error) { return []byte("my-refresh-tok"), nil },
	)

	assert.Equal(t, "google", s.Provider())

	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestOAuthRefresh_GetRefreshTokenError(t *testing.T) {
	s := strategies.NewOAuthRefreshStrategy(
		"google", "http://unused", "cid", "csec",
		func(_, _ string) ([]byte, error) { return nil, errors.New("no refresh token stored") },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get refresh token")
}

func TestOAuthRefresh_ExpiredRefreshToken_InvalidGrant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "invalid_grant"})
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "cid", "csec",
		func(_, _ string) ([]byte, error) { return []byte("expired"), nil },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, broker.ErrExpiredRefreshToken)
}

func TestOAuthRefresh_ExpiredRefreshToken_InvalidToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{"error": "invalid_token"})
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "cid", "csec",
		func(_, _ string) ([]byte, error) { return []byte("expired"), nil },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, broker.ErrExpiredRefreshToken)
}

func TestOAuthRefresh_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "cid", "csec",
		func(_, _ string) ([]byte, error) { return []byte("tok"), nil },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestOAuthRefresh_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"token_type": "Bearer"}) // no access_token
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "cid", "csec",
		func(_, _ string) ([]byte, error) { return []byte("tok"), nil },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing access_token")
}

func TestOAuthRefresh_RefreshTokenNotInResult(t *testing.T) {
	const refreshToken = "super-secret-refresh-token-must-not-log"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "short-lived-access",
			"expires_in":   300,
		})
	}))
	defer srv.Close()

	s := strategies.NewOAuthRefreshStrategy(
		"google", srv.URL, "cid", "csec",
		func(_, _ string) ([]byte, error) { return []byte(refreshToken), nil },
	)

	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	resStr := fmt.Sprintf("%+v", res)
	assert.NotContains(t, resStr, refreshToken, "refresh token must not appear in ExchangeResult metadata")
}

// ---- GitHubAppInstallationStrategy ----

func TestGitHubApp_InvalidPrivateKey_SignJWTFails(t *testing.T) {
	// Use a fresh tiny RSA key for tests (GitHub requires RSA).
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"Bad credentials"}`))
	}))
	defer srv.Close()

	// Override the endpoint by using the test server URL directly.
	// We create the strategy normally; the HTTP call to GitHub.com will fail
	// via the test server returning 401.
	s := strategies.NewGitHubAppInstallationStrategyWithURL("app-123", "install-456", key, srv.URL+"/app/installations/%s/access_tokens")

	_, err = s.Exchange(context.Background(), "", "", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, broker.ErrRevokedSession)
}

func TestGitHubApp_HappyPath(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	expiresAt := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_test_installation_token",
			"expires_at": expiresAt,
		})
	}))
	defer srv.Close()

	s := strategies.NewGitHubAppInstallationStrategyWithURL("app-123", "install-456", key, srv.URL+"/app/installations/%s/access_tokens")
	assert.Equal(t, "github", s.Provider())

	res, err := s.Exchange(context.Background(), "", "", "")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestGitHubApp_ServerError(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := strategies.NewGitHubAppInstallationStrategyWithURL("app-123", "install-456", key, srv.URL+"/app/installations/%s/access_tokens")
	_, err = s.Exchange(context.Background(), "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestGitHubApp_MissingToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"expires_at": "2099-01-01T00:00:00Z"})
	}))
	defer srv.Close()

	s := strategies.NewGitHubAppInstallationStrategyWithURL("app-123", "install-456", key, srv.URL+"/app/installations/%s/access_tokens")
	_, err = s.Exchange(context.Background(), "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing token")
}

// ---- AWSStsStrategy ----

func TestAWSSts_GetBaseCredentialsError_ReturnsUnsupported(t *testing.T) {
	s := strategies.NewAWSStsStrategy("arn:aws:iam::123456789012:role/TestRole", "us-east-1",
		func(_ string) (string, string, error) {
			return "", "", errors.New("no AWS keys configured")
		})

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.ErrorIs(t, err, broker.ErrUnsupportedExchange)
}

func TestAWSSts_HappyPath_MockHTTP(t *testing.T) {
	stsXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse>
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</SecretAccessKey>
      <SessionToken>AQoXnyc4MCoDExample</SessionToken>
      <Expiration>` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, stsXML)
	}))
	defer srv.Close()

	s := strategies.NewAWSStsStrategyWithEndpoint(
		"arn:aws:iam::123456789012:role/TestRole", "us-east-1",
		func(_ string) (string, string, error) { return "AKIAEXAMPLE", "secret-key", nil },
		srv.URL,
	)

	assert.Equal(t, "aws", s.Provider())
	res, err := s.Exchange(context.Background(), "actor", "session-abc", "ns")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestAWSSts_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := strategies.NewAWSStsStrategyWithEndpoint(
		"arn:aws:iam::123456789012:role/TestRole", "us-east-1",
		func(_ string) (string, string, error) { return "AKIA", "secret", nil },
		srv.URL,
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestAWSSts_CredentialsNotInMetadata(t *testing.T) {
	const secretKey = "wJalrXUtnFEMI-SECRET-MUST-NOT-LOG"
	stsXML := `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleResponse>
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIAEXAMPLE</AccessKeyId>
      <SecretAccessKey>` + secretKey + `</SecretAccessKey>
      <SessionToken>tok</SessionToken>
      <Expiration>` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, stsXML)
	}))
	defer srv.Close()

	s := strategies.NewAWSStsStrategyWithEndpoint(
		"arn:aws:iam::123456789012:role/TestRole", "us-east-1",
		func(_ string) (string, string, error) { return "AKIA", "base-secret", nil },
		srv.URL,
	)

	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	resStr := fmt.Sprintf("%+v", res)
	assert.NotContains(t, resStr, secretKey, "AWS secret key must not appear in ExchangeResult metadata")
}

// ---- VaultDynamicSecretStrategy ----

func TestVaultDynamic_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "vault-root-token", r.Header.Get("X-Vault-Token"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"lease_id":       "database/creds/my-role/abc123",
			"lease_duration": 3600,
			"data": map[string]any{
				"username": "v-user",
				"password": "v-pass",
			},
		})
	}))
	defer srv.Close()

	s := strategies.NewVaultDynamicSecretStrategy(
		srv.URL, "database/creds/my-role",
		func(_ string) ([]byte, error) { return []byte("vault-root-token"), nil },
	)

	assert.Equal(t, "hashicorp-vault", s.Provider())
	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestVaultDynamic_GetVaultTokenError(t *testing.T) {
	s := strategies.NewVaultDynamicSecretStrategy(
		"http://unused", "database/creds/role",
		func(_ string) ([]byte, error) { return nil, errors.New("vault not configured") },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get vault token")
}

func TestVaultDynamic_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	s := strategies.NewVaultDynamicSecretStrategy(
		srv.URL, "database/creds/role",
		func(_ string) ([]byte, error) { return []byte("tok"), nil },
	)

	_, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestVaultDynamic_RevokeLease(t *testing.T) {
	revokeCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "revoke") {
			revokeCalled = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := strategies.NewVaultDynamicSecretStrategy(
		srv.URL, "database/creds/role",
		func(_ string) ([]byte, error) { return []byte("tok"), nil },
	)

	err := s.RevokeLease(context.Background(), "db/creds/my-role/abc123", []byte("vault-token"))
	require.NoError(t, err)
	assert.True(t, revokeCalled, "revoke endpoint must be called")
}

// ---- CustomTemplateStrategy ----

func TestCustomTemplate_HappyPath(t *testing.T) {
	s, err := strategies.NewCustomTemplateStrategy(
		"myprovider",
		[]string{"session_id", "endpoint"},
		func(_ context.Context, _, _, _ string) ([]byte, time.Duration, error) {
			return []byte("session-token-value"), 30 * time.Minute, nil
		},
	)
	require.NoError(t, err)

	assert.Equal(t, "myprovider", s.Provider())

	res, err := s.Exchange(context.Background(), "actor", "session", "ns")
	require.NoError(t, err)
	assert.Equal(t, broker.FreshExchange, res.ExchangeType)
}

func TestCustomTemplate_ForbiddenOutputField_Token(t *testing.T) {
	_, err := strategies.NewCustomTemplateStrategy(
		"bad", []string{"token"}, nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestCustomTemplate_ForbiddenOutputField_AccessToken(t *testing.T) {
	_, err := strategies.NewCustomTemplateStrategy(
		"bad", []string{"access_token"}, nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestCustomTemplate_ForbiddenOutputField_Secret(t *testing.T) {
	_, err := strategies.NewCustomTemplateStrategy(
		"bad", []string{"secret"}, nil,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestCustomTemplate_ExchangeFuncError(t *testing.T) {
	s, err := strategies.NewCustomTemplateStrategy(
		"myprovider",
		[]string{"endpoint"},
		func(_ context.Context, _, _, _ string) ([]byte, time.Duration, error) {
			return nil, 0, errors.New("upstream unavailable")
		},
	)
	require.NoError(t, err)

	_, err = s.Exchange(context.Background(), "actor", "session", "ns")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream unavailable")
}

func TestCustomTemplate_SafeOutputFields_Allowed(t *testing.T) {
	// Fields that are NOT in the forbidden list must be accepted.
	for _, field := range []string{"session_id", "endpoint_url", "region", "account_id"} {
		s, err := strategies.NewCustomTemplateStrategy(
			"myprovider",
			[]string{field},
			func(_ context.Context, _, _, _ string) ([]byte, time.Duration, error) {
				return []byte("val"), time.Minute, nil
			},
		)
		require.NoError(t, err, "field %q should be accepted", field)
		res, err := s.Exchange(context.Background(), "actor", "session", "ns")
		require.NoError(t, err)
		assert.Equal(t, broker.FreshExchange, res.ExchangeType)
	}
}
