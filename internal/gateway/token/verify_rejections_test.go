package token_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/keylatch/keylatch/internal/gateway/token"
)

func scMint(t *testing.T, key []byte, storePath string, mutate func(*token.TokenSpec)) (string, *token.Token) {
	t.Helper()
	spec := token.TokenSpec{
		Actor:        "actor",
		Capabilities: []string{"openrouter.chat"},
		TTL:          time.Hour,
		SigningKey:   key,
		StorePath:    storePath,
	}
	if mutate != nil {
		mutate(&spec)
	}
	jwtStr, tok, err := token.Mint(spec)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	return jwtStr, tok
}

func scRewriteStore(t *testing.T, storePath string, mutate func([]token.Token) []token.Token) {
	t.Helper()
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var toks []token.Token
	if err := json.Unmarshal(data, &toks); err != nil {
		t.Fatal(err)
	}
	toks = mutate(toks)
	out, err := json.Marshal(toks)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(storePath, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

func scSign(t *testing.T, method jwt.SigningMethod, key any, claims jwt.MapClaims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestMint_RejectsBadKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		_, _, err := token.Mint(token.TokenSpec{SigningKey: make([]byte, n)})
		if err == nil || !strings.Contains(err.Error(), "32 bytes") {
			t.Errorf("key len %d: want 32-byte error, got %v", n, err)
		}
	}
}

func TestMint_MaxUsesRequiresStorePath(t *testing.T) {
	_, _, err := token.Mint(token.TokenSpec{SigningKey: testSigningKey(t), MaxUses: 1})
	if err == nil || !strings.Contains(err.Error(), "StorePath") {
		t.Fatalf("want StorePath error, got %v", err)
	}
}

func TestMint_DefaultTTLIsOneHour(t *testing.T) {
	_, tok := scMint(t, testSigningKey(t), testStorePath(t), func(s *token.TokenSpec) { s.TTL = 0 })
	got := tok.ExpiresAt.Sub(tok.IssuedAt)
	if got != time.Hour {
		t.Fatalf("default TTL = %v, want 1h", got)
	}
}

func TestMint_HashesCommandAndCWDNotRaw(t *testing.T) {
	storePath := testStorePath(t)
	_, tok := scMint(t, testSigningKey(t), storePath, func(s *token.TokenSpec) {
		s.Command = "deploy --prod"
		s.CWD = "/srv/app"
	})
	if tok.CommandHash == "" || tok.CWDHash == "" || tok.CommandHash == tok.CWDHash {
		t.Fatalf("unexpected hashes: cmd=%q cwd=%q", tok.CommandHash, tok.CWDHash)
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "deploy --prod") || strings.Contains(string(data), "/srv/app") {
		t.Fatal("raw command or cwd persisted in token store")
	}
}

func TestMint_PersistFailureReturnsSentinel(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := token.Mint(token.TokenSpec{
		SigningKey: testSigningKey(t),
		StorePath:  filepath.Join(blocker, "tokens.json"),
	})
	if !errors.Is(err, token.ErrTokenPersistFailed) {
		t.Fatalf("want ErrTokenPersistFailed, got %v", err)
	}
}

func TestMintAndRevokeHooksFire(t *testing.T) {
	var minted, revoked atomic.Int32
	token.SetMintHook(func() { minted.Add(1) })
	token.SetRevokeHook(func() { revoked.Add(1) })
	t.Cleanup(func() {
		token.SetMintHook(nil)
		token.SetRevokeHook(nil)
	})

	storePath := testStorePath(t)
	_, tok := scMint(t, testSigningKey(t), storePath, nil)
	if minted.Load() != 1 {
		t.Fatalf("mint hook calls = %d, want 1", minted.Load())
	}
	if err := token.Revoke(tok.ID, storePath); err != nil {
		t.Fatal(err)
	}
	if revoked.Load() != 1 {
		t.Fatalf("revoke hook calls = %d, want 1", revoked.Load())
	}
	if err := token.Revoke("missing", storePath); !errors.Is(err, token.ErrTokenNotFound) {
		t.Fatalf("want ErrTokenNotFound, got %v", err)
	}
	if revoked.Load() != 1 {
		t.Fatal("revoke hook must not fire when revoke fails")
	}
}

func TestVerify_RejectsBadKeyLength(t *testing.T) {
	_, err := token.Verify("x.y.z", nil, make([]byte, 16), "")
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("want 32-byte error, got %v", err)
	}
}

func TestVerify_RejectsExpiredJWT(t *testing.T) {
	key := testSigningKey(t)
	past := time.Now().Add(-time.Hour)
	s := scSign(t, jwt.SigningMethodHS256, key, jwt.MapClaims{
		"jti": "id-1",
		"iat": past.Add(-time.Hour).Unix(),
		"exp": past.Unix(),
	})
	_, err := token.Verify(s, nil, key, testStorePath(t))
	if !errors.Is(err, token.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerify_RejectsExpiredStoreRecordWithLiveJWT(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, tok := scMint(t, key, storePath, nil)
	scRewriteStore(t, storePath, func(ts []token.Token) []token.Token {
		for i := range ts {
			if ts[i].ID == tok.ID {
				ts[i].ExpiresAt = time.Now().Add(-time.Minute)
			}
		}
		return ts
	})
	if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
}

func TestVerify_RejectsTamperedClaims(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, _ := scMint(t, key, storePath, nil)

	parts := strings.Split(jwtStr, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT shape: %d parts", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["caps"] = []string{"openrouter.chat", "admin.*"}
	claims["llm_session"] = false
	widened, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString(widened) + "." + parts[2]

	_, err = token.Verify(forged, nil, key, storePath)
	if err == nil || !errors.Is(err, jwt.ErrTokenSignatureInvalid) {
		t.Fatalf("want signature invalid, got %v", err)
	}
}

func TestVerify_RejectsTamperedSignature(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, _ := scMint(t, key, storePath, nil)
	last := jwtStr[len(jwtStr)-2]
	repl := byte('A')
	if last == 'A' {
		repl = 'B'
	}
	forged := jwtStr[:len(jwtStr)-2] + string(repl) + jwtStr[len(jwtStr)-1:]
	if _, err := token.Verify(forged, nil, key, storePath); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerify_RejectsOtherAlgorithms(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	_, tok := scMint(t, key, storePath, nil)
	claims := jwt.MapClaims{"jti": tok.ID, "exp": time.Now().Add(time.Hour).Unix()}

	cases := map[string]string{
		"HS512": scSign(t, jwt.SigningMethodHS512, key, claims),
		"none":  scSign(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, claims),
	}
	for name, s := range cases {
		_, err := token.Verify(s, nil, key, storePath)
		if err == nil || !strings.Contains(err.Error(), "token: invalid") {
			t.Errorf("%s: want invalid-token error, got %v", name, err)
		}
	}
}

func TestVerify_RejectsGarbage(t *testing.T) {
	key := testSigningKey(t)
	for _, s := range []string{"", "not-a-jwt", "a.b.c"} {
		if _, err := token.Verify(s, nil, key, testStorePath(t)); err == nil {
			t.Errorf("Verify(%q) accepted", s)
		}
	}
}

func TestVerify_ValidSignatureUnknownToStore(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	scMint(t, key, storePath, nil)
	s := scSign(t, jwt.SigningMethodHS256, key, jwt.MapClaims{
		"jti": "never-minted",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := token.Verify(s, nil, key, storePath); !errors.Is(err, token.ErrTokenNotFound) {
		t.Fatalf("want ErrTokenNotFound, got %v", err)
	}
	if _, err := token.Verify(s, nil, key, ""); !errors.Is(err, token.ErrTokenNotFound) {
		t.Fatalf("empty store path: want ErrTokenNotFound, got %v", err)
	}
}

func TestVerify_CorruptStoreFailsClosed(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, _ := scMint(t, key, storePath, nil)
	if err := os.WriteFile(storePath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenNotFound) {
		t.Fatalf("want ErrTokenNotFound, got %v", err)
	}
	if _, err := token.List(token.ListOpts{}, storePath); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("List: want parse error, got %v", err)
	}
	if err := token.Revoke("anything", storePath); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("Revoke: want parse error, got %v", err)
	}
}

func TestList_UnreadableStore(t *testing.T) {
	dir := t.TempDir()
	if _, err := token.List(token.ListOpts{}, dir); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("want read error for directory store, got %v", err)
	}
	got, err := token.List(token.ListOpts{}, "")
	if err != nil || got != nil {
		t.Fatalf("empty store path: got %v, %v", got, err)
	}
	got, err = token.List(token.ListOpts{}, filepath.Join(dir, "absent.json"))
	if err != nil || got != nil {
		t.Fatalf("missing store: got %v, %v", got, err)
	}
}

func TestVerify_FDNonceBadBase64(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, _ := scMint(t, key, storePath, func(s *token.TokenSpec) { s.FDNonce = []byte("0123456789abcdef0123456789abcdef") })
	req := httptest.NewRequest("POST", "/x", nil)
	req.Header.Set("X-Keylatch-FD-Nonce", "!!!not base64!!!")
	if _, err := token.Verify(jwtStr, req, key, storePath); !errors.Is(err, token.ErrFDNonceMismatch) {
		t.Fatalf("want ErrFDNonceMismatch, got %v", err)
	}
	req.Header.Set("X-Keylatch-FD-Nonce", base64.StdEncoding.EncodeToString([]byte("wrong-nonce")))
	if _, err := token.Verify(jwtStr, req, key, storePath); !errors.Is(err, token.ErrFDNonceMismatch) {
		t.Fatalf("wrong nonce: want ErrFDNonceMismatch, got %v", err)
	}
}

func TestVerify_InMemoryUseCounterWithoutLogPath(t *testing.T) {
	key := testSigningKey(t)
	storePath := testStorePath(t)
	jwtStr, tok := scMint(t, key, storePath, nil)

	setUses := func(maxUses, remaining int) {
		scRewriteStore(t, storePath, func(ts []token.Token) []token.Token {
			for i := range ts {
				if ts[i].ID == tok.ID {
					ts[i].MaxUses = maxUses
					ts[i].UsesRemaining = remaining
					ts[i].ConsumptionLogPath = ""
				}
			}
			return ts
		})
	}

	setUses(2, 0)
	if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenExhausted) {
		t.Fatalf("want ErrTokenExhausted, got %v", err)
	}
	setUses(2, 1)
	got, err := token.Verify(jwtStr, nil, key, storePath)
	if err != nil {
		t.Fatalf("want success, got %v", err)
	}
	if got.UsesRemaining != 0 {
		t.Fatalf("UsesRemaining = %d, want 0", got.UsesRemaining)
	}
}

func TestVerify_ConsumptionLogFailuresFailClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix flock implementation")
	}
	key := testSigningKey(t)

	setLog := func(t *testing.T, storePath, id, logPath string) {
		scRewriteStore(t, storePath, func(ts []token.Token) []token.Token {
			for i := range ts {
				if ts[i].ID == id {
					ts[i].ConsumptionLogPath = logPath
				}
			}
			return ts
		})
	}

	t.Run("log dir blocked by file", func(t *testing.T) {
		storePath := testStorePath(t)
		jwtStr, tok := scMint(t, key, storePath, func(s *token.TokenSpec) { s.MaxUses = 3 })
		blocker := filepath.Join(t.TempDir(), "file")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		setLog(t, storePath, tok.ID, filepath.Join(blocker, "sub", "x.log"))
		if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenExhausted) {
			t.Fatalf("want ErrTokenExhausted, got %v", err)
		}
	})

	t.Run("lock path is a directory", func(t *testing.T) {
		storePath := testStorePath(t)
		jwtStr, tok := scMint(t, key, storePath, func(s *token.TokenSpec) { s.MaxUses = 3 })
		logPath := filepath.Join(t.TempDir(), "x.log")
		if err := os.Mkdir(logPath+".lock", 0o700); err != nil {
			t.Fatal(err)
		}
		setLog(t, storePath, tok.ID, logPath)
		if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenExhausted) {
			t.Fatalf("want ErrTokenExhausted, got %v", err)
		}
	})

	t.Run("log path is a directory", func(t *testing.T) {
		storePath := testStorePath(t)
		jwtStr, tok := scMint(t, key, storePath, func(s *token.TokenSpec) { s.MaxUses = 3 })
		logPath := filepath.Join(t.TempDir(), "x.log")
		if err := os.Mkdir(logPath, 0o700); err != nil {
			t.Fatal(err)
		}
		setLog(t, storePath, tok.ID, logPath)
		if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenExhausted) {
			t.Fatalf("want ErrTokenExhausted, got %v", err)
		}
	})
}

func TestRevoke_WriteFailureLeavesTokenValid(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	key := testSigningKey(t)
	dir := filepath.Join(t.TempDir(), "store")
	storePath := filepath.Join(dir, "tokens.json")
	jwtStr, tok := scMint(t, key, storePath, nil)

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := token.Revoke(tok.ID, storePath)
	if err == nil || !strings.Contains(err.Error(), "write tmp") {
		t.Fatalf("want write tmp error, got %v", err)
	}
	if _, err := token.Verify(jwtStr, nil, key, storePath); err != nil {
		t.Fatalf("token should remain valid after failed revoke: %v", err)
	}
}

func TestStoreLock_DirectoryLockPathFallsBack(t *testing.T) {
	storePath := testStorePath(t)
	if err := os.Mkdir(storePath+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	key := testSigningKey(t)
	jwtStr, tok := scMint(t, key, storePath, nil)
	if _, err := token.Verify(jwtStr, nil, key, storePath); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := token.Revoke(tok.ID, storePath); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := token.Verify(jwtStr, nil, key, storePath); !errors.Is(err, token.ErrTokenRevoked) {
		t.Fatalf("want ErrTokenRevoked, got %v", err)
	}
}

func TestStoreFile_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	storePath := filepath.Join(t.TempDir(), "nested", "tokens.json")
	scMint(t, testSigningKey(t), storePath, nil)
	st, err := os.Stat(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("store mode = %v, want 0600", st.Mode().Perm())
	}
	dst, err := os.Stat(filepath.Dir(storePath))
	if err != nil {
		t.Fatal(err)
	}
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode = %v, want 0700", dst.Mode().Perm())
	}
}
