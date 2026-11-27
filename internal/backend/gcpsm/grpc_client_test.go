package gcpsm_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	secretmanagerpb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/googleapis/gax-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/gcpsm"
)

// bkGCPServer is an in-process Secret Manager gRPC server so the real SDK
// client (and its concrete SecretIterator) can be exercised.
type bkGCPServer struct {
	secretmanagerpb.UnimplementedSecretManagerServiceServer

	mu        sync.Mutex
	secrets   map[string][]byte
	listErr   error
	listPages [][]string
	parents   []string
}

func (s *bkGCPServer) ListSecrets(_ context.Context, req *secretmanagerpb.ListSecretsRequest) (*secretmanagerpb.ListSecretsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.parents = append(s.parents, req.GetParent())
	if s.listErr != nil {
		return nil, s.listErr
	}
	idx := 0
	if tok := req.GetPageToken(); tok != "" {
		idx = int(tok[0] - '0')
	}
	resp := &secretmanagerpb.ListSecretsResponse{}
	if idx < len(s.listPages) {
		for _, n := range s.listPages[idx] {
			resp.Secrets = append(resp.Secrets, &secretmanagerpb.Secret{Name: n})
		}
		if idx+1 < len(s.listPages) {
			resp.NextPageToken = string(rune('0' + idx + 1))
		}
	}
	return resp, nil
}

func (s *bkGCPServer) AccessSecretVersion(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.secrets[req.GetName()]
	if !ok {
		return nil, status.Error(codes.NotFound, "no such secret")
	}
	return &secretmanagerpb.AccessSecretVersionResponse{
		Name:    req.GetName(),
		Payload: &secretmanagerpb.SecretPayload{Data: v},
	}, nil
}

func bkGCPOpen(t *testing.T, srv *bkGCPServer) *gcpsm.GCPSecretManagerBackend {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	secretmanagerpb.RegisterSecretManagerServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)

	b, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID:     "proj-x",
		ClientOptions: []option.ClientOption{option.WithGRPCConn(conn), option.WithoutAuthentication()},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestGCPList_RealClientPagesAndPrefix(t *testing.T) {
	srv := &bkGCPServer{listPages: [][]string{
		{"projects/proj-x/secrets/app-db", "projects/proj-x/secrets/other"},
		{"projects/proj-x/secrets/app-api"},
	}}
	b := bkGCPOpen(t, srv)

	all, err := b.List(context.Background(), "")
	require.NoError(t, err)
	var names []string
	for _, e := range all {
		assert.True(t, e.Exists)
		assert.Equal(t, "gcp-sm", e.Backend)
		names = append(names, e.Path)
	}
	sort.Strings(names)
	assert.Equal(t, []string{"app-api", "app-db", "other"}, names)

	filtered, err := b.List(context.Background(), "app-")
	require.NoError(t, err)
	require.Len(t, filtered, 2)
	for _, e := range filtered {
		assert.Contains(t, []string{"app-api", "app-db"}, e.Path)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	require.NotEmpty(t, srv.parents)
	assert.Equal(t, "projects/proj-x", srv.parents[0])
}

func TestGCPList_RealClientEmpty(t *testing.T) {
	b := bkGCPOpen(t, &bkGCPServer{})
	entries, err := b.List(context.Background(), "")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestGCPList_RealClientErrorIsWrapped(t *testing.T) {
	b := bkGCPOpen(t, &bkGCPServer{listErr: status.Error(codes.PermissionDenied, "denied")})
	_, err := b.List(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gcp-sm List")
	st, ok := status.FromError(errors.Unwrap(err))
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}

func TestGCPGet_RealClientRoundTripAndNotFound(t *testing.T) {
	val := []byte("payload-value")
	b := bkGCPOpen(t, &bkGCPServer{secrets: map[string][]byte{
		"projects/proj-x/secrets/db/versions/latest": val,
	}})

	got, meta, err := b.Get(context.Background(), "db")
	require.NoError(t, err)
	assert.Equal(t, val, got)
	assert.Equal(t, "db", meta.Path)

	_, _, err = b.Get(context.Background(), "nope")
	require.ErrorIs(t, err, backend.ErrNotFound)
}

func TestGCPOpen_InvalidCredentialsFile(t *testing.T) {
	credPath := filepath.Join(t.TempDir(), "sa.json")
	require.NoError(t, os.WriteFile(credPath, []byte("{not json"), 0o600))

	_, err := gcpsm.Open(context.Background(), gcpsm.Options{
		ProjectID:       "proj-x",
		CredentialsFile: credPath,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gcp-sm backend: create client")
}

func TestGCPFactory_ViaRegistry(t *testing.T) {
	credPath := filepath.Join(t.TempDir(), "missing.json")
	factory, ok := backend.Default.Get("gcp-sm")
	require.True(t, ok)

	_, err := factory(context.Background(), backend.BackendConfig{
		Name:     "gcp-sm",
		Settings: map[string]any{"project_id": "proj-x", "credentials_json": credPath},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create client")

	_, err = factory(context.Background(), backend.BackendConfig{
		Name:     "gcp-sm",
		Settings: map[string]any{"project_id": "proj-x", "bogus": "x"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid settings")
}

// bkGCPSetClient scripts AddSecretVersion results per call.
type bkGCPSetClient struct {
	nilPayloadGCPClient
	addErrs  []error
	addCalls int
	created  []string
}

func (m *bkGCPSetClient) AddSecretVersion(_ context.Context, _ *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	i := m.addCalls
	m.addCalls++
	if i < len(m.addErrs) {
		return nil, m.addErrs[i]
	}
	return &secretmanagerpb.SecretVersion{}, nil
}

func (m *bkGCPSetClient) CreateSecret(_ context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	m.created = append(m.created, req.GetSecretId())
	return &secretmanagerpb.Secret{}, nil
}

func TestGCPSet_ErrorMapping(t *testing.T) {
	notFound := status.Error(codes.NotFound, "missing")
	denied := status.Error(codes.PermissionDenied, "denied")
	secret := []byte("very-private-value")

	cases := []struct {
		name     string
		addErrs  []error
		wantErr  string
		wantCode codes.Code
		created  bool
	}{
		{name: "create then add version fails", addErrs: []error{notFound, denied}, wantErr: "(add version)", wantCode: codes.PermissionDenied, created: true},
		{name: "non not-found add error", addErrs: []error{denied}, wantErr: `gcp-sm Set "k"`, wantCode: codes.PermissionDenied},
		{name: "create then add ok", addErrs: []error{notFound}, created: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := &bkGCPSetClient{addErrs: tc.addErrs}
			b, err := gcpsm.Open(context.Background(), gcpsm.Options{ProjectID: "p", Client: client})
			require.NoError(t, err)

			err = b.Set(context.Background(), "k", secret, backend.Meta{})
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.NotContains(t, err.Error(), string(secret))
				assert.Equal(t, tc.wantCode, status.Code(errors.Unwrap(err)))
			}
			if tc.created {
				assert.Equal(t, []string{"k"}, client.created)
			} else {
				assert.Empty(t, client.created)
			}
		})
	}
}
