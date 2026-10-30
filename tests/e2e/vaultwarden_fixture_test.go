//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/backend/bw"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

type vaultwardenFixture struct {
	server, organization, collection, email, password, ca, bin string
}

// Provision only a disposable loopback service; never use a developer's account.
func newVaultwardenFixture(t *testing.T) *vaultwardenFixture {
	t.Helper()
	endpoint := os.Getenv("KEYLATCH_E2E_VAULTWARDEN_URL")
	if endpoint == "" {
		if os.Getenv("KEYLATCH_E2E_BW_REQUIRED") == "1" {
			t.Fatal("KEYLATCH_E2E_VAULTWARDEN_URL is required")
		}
		t.Skip("set KEYLATCH_E2E_VAULTWARDEN_URL to a disposable loopback Vaultwarden service")
	}
	u, err := url.Parse(endpoint)
	require.NoError(t, err)
	require.True(t, u.Scheme == "http" && u.Hostname() == "127.0.0.1" && u.Port() != "" && u.User == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "", "fixture must be an exact HTTP loopback origin")
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = &http.Transport{Proxy: nil}
	server := httptest.NewTLSServer(proxy)
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "fixture-ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600))
	name := os.Getenv("KEYLATCH_E2E_BW_BIN")
	if name == "" {
		name = "bw"
	}
	bin, err := exec.LookPath(name)
	require.NoError(t, err, "install the pinned Bitwarden CLI fixture dependency")
	bin, err = filepath.Abs(bin)
	require.NoError(t, err)
	f := &vaultwardenFixture{server: server.URL, collection: "Restore tests", email: "keylatch-" + hex.EncodeToString(fixtureRandom(t, 12)) + "@example.invalid", password: base64.RawURLEncoding.EncodeToString(fixtureRandom(t, 32)), ca: ca, bin: bin}
	client := server.Client()
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	master := pbkdf2.Key([]byte(f.password), []byte(f.email), 600000, 32, sha256.New)
	defer clear(master)
	hash := base64.StdEncoding.EncodeToString(pbkdf2.Key(master, []byte(f.password), 1, 32, sha256.New))
	stretched := make([]byte, 64)
	defer clear(stretched)
	_, err = io.ReadFull(hkdf.Expand(sha256.New, master, []byte("enc")), stretched[:32])
	require.NoError(t, err)
	_, err = io.ReadFull(hkdf.Expand(sha256.New, master, []byte("mac")), stretched[32:])
	require.NoError(t, err)
	userKey := fixtureRandom(t, 64)
	defer clear(userKey)
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	defer clear(privateDER)
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	require.NoError(t, err)
	var verification string
	fixtureJSON(t, client, f.server+"/identity/accounts/register/send-verification-email", "", map[string]any{"email": f.email}, &verification)
	fixtureJSON(t, client, f.server+"/identity/accounts/register/finish", "", map[string]any{
		"email": f.email, "emailVerificationToken": verification,
		"masterPasswordHash": hash, "key": fixtureEncrypt(t, stretched, userKey), "kdf": 0, "kdfIterations": 600000,
		"keys": map[string]string{"publicKey": base64.StdEncoding.EncodeToString(publicDER), "encryptedPrivateKey": fixtureEncrypt(t, userKey, privateDER)},
	}, nil)
	form := url.Values{"grant_type": {"password"}, "client_id": {"cli"}, "scope": {"api offline_access"}, "username": {f.email}, "password": {hash}, "deviceIdentifier": {hex.EncodeToString(fixtureRandom(t, 16))}, "deviceName": {"keylatch-test"}, "deviceType": {"8"}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.server+"/identity/connect/token", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var auth struct {
		AccessToken string `json:"access_token"`
	}
	fixtureResponse(t, client, req, &auth)
	require.NotEmpty(t, auth.AccessToken)
	orgKey := fixtureRandom(t, 64)
	defer clear(orgKey)
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &private.PublicKey, orgKey, nil)
	require.NoError(t, err)
	var organization struct {
		ID string `json:"id"`
	}
	fixtureJSON(t, client, f.server+"/api/organizations", auth.AccessToken, map[string]any{
		"billingEmail": f.email, "name": "Keylatch disposable tests", "planType": 0,
		"key": "3." + base64.StdEncoding.EncodeToString(wrapped), "collectionName": fixtureEncrypt(t, orgKey, []byte(f.collection)),
	}, &organization)
	require.NotEmpty(t, organization.ID)
	f.organization = organization.ID
	t.Cleanup(func() { f.password = "" })
	return f
}

func fixtureRandom(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	_, err := rand.Read(b)
	require.NoError(t, err)
	return b
}

// Bitwarden's authenticated type-2 cipher format for generated fixture keys.
func fixtureEncrypt(t *testing.T, key, value []byte) string {
	t.Helper()
	block, err := aes.NewCipher(key[:32])
	require.NoError(t, err)
	iv := fixtureRandom(t, aes.BlockSize)
	padding := aes.BlockSize - len(value)%aes.BlockSize
	plain := append(bytes.Clone(value), bytes.Repeat([]byte{byte(padding)}, padding)...)
	defer clear(plain)
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	mac := hmac.New(sha256.New, key[32:])
	_, _ = mac.Write(iv)
	_, _ = mac.Write(ciphertext)
	return "2." + base64.StdEncoding.EncodeToString(iv) + "|" + base64.StdEncoding.EncodeToString(ciphertext) + "|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func fixtureJSON(t *testing.T, client *http.Client, endpoint, token string, body, result any) {
	t.Helper()
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	fixtureResponse(t, client, req, result)
}

func fixtureResponse(t *testing.T, client *http.Client, req *http.Request, result any) {
	t.Helper()
	response, err := client.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	require.True(t, response.StatusCode >= 200 && response.StatusCode < 300, "fixture endpoint %s returned HTTP %d", req.URL.Path, response.StatusCode)
	if result != nil {
		require.NoError(t, json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(result))
	}
}

type fixtureRunner struct{ env []string }

func (r fixtureRunner) Run(ctx context.Context, name string, args []string, input []byte) ([]byte, []byte, int, error) {
	return r.RunEnv(ctx, name, args, input, nil)
}

func (r fixtureRunner) RunEnv(ctx context.Context, name string, args []string, input []byte, extra []string) ([]byte, []byte, int, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return kexec.DefaultRunner.RunEnv(ctx, name, args, input, append(append([]string{}, r.env...), extra...))
}

func (f *vaultwardenFixture) freshClient(t *testing.T) (*bw.BitwardenBackend, fixtureRunner) {
	t.Helper()
	runner := fixtureRunner{env: []string{"BITWARDENCLI_APPDATA_DIR=" + t.TempDir(), "NODE_EXTRA_CA_CERTS=" + f.ca, "BW_SESSION=", "BW_NOINTERACTION=true", "KEYLATCH_TEST_BW_PASSWORD=" + f.password}}
	run := func(args ...string) []byte {
		out, _, code, err := runner.Run(t.Context(), f.bin, args, nil)
		require.NoError(t, err)
		require.Zero(t, code, "fixture bw %s failed (output withheld)", args[0])
		return out
	}
	run("config", "server", f.server)
	token := strings.TrimSpace(string(run("login", f.email, "--passwordenv", "KEYLATCH_TEST_BW_PASSWORD", "--raw")))
	require.NotEmpty(t, token)
	runner.env = append(runner.env, "BW_SESSION="+token, "KEYLATCH_TEST_BW_PASSWORD=")
	run("sync")
	b, err := bw.Open(bw.Options{Server: f.server, OrganizationID: f.organization, Namespaces: map[string]string{"work": f.collection}, Bin: f.bin, Runner: runner, Env: func(key string) string {
		if key == "BW_SESSION" {
			return token
		}
		return ""
	}})
	require.NoError(t, err)
	return b, runner
}
