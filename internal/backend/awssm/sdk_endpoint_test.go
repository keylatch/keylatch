package awssm_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/awssm"
)

type bkAWSCall struct {
	target string
	body   map[string]any
	auth   string
}

// bkAWSServer emulates the Secrets Manager JSON protocol so the real SDK
// client built by Open is exercised end to end.
type bkAWSServer struct {
	mu      sync.Mutex
	calls   []bkAWSCall
	secrets map[string]string
	status  int
	errType string
}

func (s *bkAWSServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	target := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "secretsmanager.")

	s.mu.Lock()
	s.calls = append(s.calls, bkAWSCall{target: target, body: body, auth: r.Header.Get("Authorization")})
	status, errType := s.status, s.errType
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	if errType != "" {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, `{"__type":"`+errType+`","message":"simulated"}`)
		return
	}

	switch target {
	case "GetSecretValue":
		id, _ := body["SecretId"].(string)
		v, ok := s.secrets[id]
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"__type":"ResourceNotFoundException","message":"missing"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Name": id, "SecretString": v, "ARN": "arn:test:" + id})
	case "ListSecrets":
		_ = json.NewEncoder(w).Encode(map[string]any{"SecretList": []map[string]any{{"Name": "svc-a", "ARN": "arn:test:svc-a"}}})
	default:
		_, _ = io.WriteString(w, `{}`)
	}
}

func (s *bkAWSServer) lastCall(t *testing.T) bkAWSCall {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.calls)
	return s.calls[len(s.calls)-1]
}

func bkAWSEnv(t *testing.T, endpoint string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	for _, k := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ENDPOINT_URL", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_ARN"} {
		t.Setenv(k, "")
		require.NoError(t, os.Unsetenv(k))
	}
	t.Setenv("AWS_ENDPOINT_URL_SECRETS_MANAGER", endpoint)
	t.Setenv("AWS_MAX_ATTEMPTS", "1")
}

func bkAWSFactoryOpen(t *testing.T, settings map[string]any) (backend.Backend, error) {
	t.Helper()
	f, ok := backend.Default.Get("aws-sm")
	require.True(t, ok)
	return f(context.Background(), backend.BackendConfig{Name: "aws-sm", Settings: settings})
}

func bkAWSCreds() (string, string) {
	return "test" + "-access-id", "test" + "-secret-" + strings.Repeat("x", 8)
}

func TestAWSRealClient_GetAndNotFoundMapping(t *testing.T) {
	srv := &bkAWSServer{secrets: map[string]string{"db/pass": "s3cr3t-value"}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	bkAWSEnv(t, ts.URL)

	ak, sk := bkAWSCreds()
	b, err := awssm.Open(context.Background(), awssm.Options{Region: "eu-west-1", AccessKey: ak, SecretKey: sk})
	require.NoError(t, err)
	assert.Equal(t, "aws-sm:eu-west-1", b.ID())

	val, meta, err := b.Get(context.Background(), "db/pass")
	require.NoError(t, err)
	assert.Equal(t, []byte("s3cr3t-value"), val)
	assert.Equal(t, backend.ID("arn:test:db/pass"), meta.Accessor)

	call := srv.lastCall(t)
	assert.Contains(t, call.auth, ak, "static credentials must sign requests")
	assert.NotContains(t, call.auth, sk, "secret key must never be sent in clear")

	_, _, err = b.Get(context.Background(), "absent")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

func TestAWSRealClient_ServiceErrorsAreWrapped(t *testing.T) {
	srv := &bkAWSServer{status: http.StatusBadRequest, errType: "AccessDeniedException"}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	bkAWSEnv(t, ts.URL)

	ak, sk := bkAWSCreds()
	b, err := awssm.Open(context.Background(), awssm.Options{Region: "us-east-1", AccessKey: ak, SecretKey: sk})
	require.NoError(t, err)

	_, _, err = b.Get(context.Background(), "x")
	require.Error(t, err)
	assert.NotErrorIs(t, err, backend.ErrNotFound)
	assert.Contains(t, err.Error(), `aws-sm Get "x"`)
	assert.Contains(t, err.Error(), "AccessDenied")

	_, err = b.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws-sm List")

	err = b.Set(context.Background(), "x", []byte("never-in-error"), backend.Meta{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "(describe)")
	assert.NotContains(t, err.Error(), "never-in-error")
}

func TestAWSFactory_ForceDeleteAndSettings(t *testing.T) {
	srv := &bkAWSServer{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	bkAWSEnv(t, ts.URL)
	ak, sk := bkAWSCreds()

	for _, tc := range []struct {
		force string
		want  bool
	}{{"TRUE", true}, {"false", false}, {"", false}} {
		settings := map[string]any{"region": "us-east-1", "access_key_id": ak, "secret_access_key": sk}
		if tc.force != "" {
			settings["force_delete"] = tc.force
		}
		b, err := bkAWSFactoryOpen(t, settings)
		require.NoError(t, err)
		require.NoError(t, b.Delete(context.Background(), "gone"))
		call := srv.lastCall(t)
		assert.Equal(t, "DeleteSecret", call.target)
		assert.Equal(t, "gone", call.body["SecretId"])
		assert.Equal(t, tc.want, call.body["ForceDeleteWithoutRecovery"], "force_delete=%q", tc.force)
	}

	entries, err := func() ([]backend.Entry, error) {
		b, err := bkAWSFactoryOpen(t, map[string]any{"region": "us-east-1", "access_key_id": ak, "secret_access_key": sk})
		require.NoError(t, err)
		return b.List(context.Background(), "svc-")
	}()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "svc-a", entries[0].Path)

	_, err = bkAWSFactoryOpen(t, map[string]any{"region": "us-east-1", "unknown_key": "x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")
}

func TestAWSOpen_LoadConfigFailure(t *testing.T) {
	bkAWSEnv(t, "http://127.0.0.1:1")
	t.Setenv("AWS_PROFILE", "profile-that-does-not-exist")

	_, err := awssm.Open(context.Background(), awssm.Options{Region: "us-east-1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "aws-sm backend: load config")
}
