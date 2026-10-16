package keyops

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/keylatch/keylatch/internal/audit"
)

var human = Caller{Kind: "human"}
var agentCaller = Caller{Kind: "agent", Constrained: true}

func service(t *testing.T, p PolicySource, keys mapKeys) (*Service, *captureAudit) {
	t.Helper()
	cap := &captureAudit{}
	s, err := New(p, keys, cap)
	if err != nil {
		t.Fatal(err)
	}
	return s, cap
}

func TestSignVerifyEveryAlgorithm(t *testing.T) {
	k := newTestKeys(t)
	cases := []struct {
		alg string
		key []byte
	}{
		{HS256, k.hmac}, {HS384, k.hmac}, {HS512, k.hmac},
		{EdDSA, k.ed}, {ES256, k.es256}, {ES384, k.es384}, {PS256, k.rsaKey}, {RS256, k.rsaKey},
	}
	msg := []byte("release 1.2.3")
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			s, _ := service(t, fullPolicy("k", []string{"sign", "verify"}, tc.alg), mapKeys{"k": tc.key})
			signed, err := s.Do(context.Background(), human, Request{Operation: OpSign, Connection: "app-local", Alg: tc.alg, Input: msg})
			if err != nil {
				t.Fatal(err)
			}
			ok, err := s.Do(context.Background(), human, Request{Operation: OpVerify, Connection: "app-local", Alg: tc.alg, Input: msg, Signature: signed.Output})
			if err != nil || !ok.Valid {
				t.Fatalf("signature did not verify: valid=%v err=%v", ok.Valid, err)
			}
			bad, err := s.Do(context.Background(), human, Request{Operation: OpVerify, Connection: "app-local", Alg: tc.alg, Input: []byte("other"), Signature: signed.Output})
			if err != nil || bad.Valid {
				t.Fatalf("a signature over different input verified: valid=%v err=%v", bad.Valid, err)
			}
		})
	}
}

func TestHMACMatchesStandardLibrary(t *testing.T) {
	k := newTestKeys(t)
	sig, err := Sign(HS384, k.hmac, []byte("x"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != sha512.Size384 {
		t.Fatalf("HS384 length %d", len(sig))
	}
	sig, _ = Sign(HS256, k.hmac, []byte("x"), false)
	if len(sig) != sha256.Size {
		t.Fatalf("HS256 length %d", len(sig))
	}
}

func TestEncryptDecryptRoundTripAndFormats(t *testing.T) {
	k := newTestKeys(t)
	for name, key := range map[string][]byte{
		"raw":    k.aes,
		"hex":    []byte(hex.EncodeToString(k.aes)),
		"base64": []byte(strings.TrimSpace(string(encodings(k.aes)[3]))),
	} {
		t.Run(name, func(t *testing.T) {
			s, _ := service(t, fullPolicy("k", []string{"encrypt", "decrypt"}, A256GCM), mapKeys{"k": key})
			enc, err := s.Do(context.Background(), human, Request{Operation: OpEncrypt, Connection: "app-local", Input: []byte("secret data"), AAD: []byte("ctx")})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(enc.Output, []byte("secret data")) {
				t.Fatal("ciphertext contains the plaintext")
			}
			dec, err := s.Do(context.Background(), human, Request{Operation: OpDecrypt, Connection: "app-local", Input: enc.Output, AAD: []byte("ctx")})
			if err != nil || string(dec.Output) != "secret data" {
				t.Fatalf("decrypt: %q %v", dec.Output, err)
			}
			if _, err := s.Do(context.Background(), human, Request{Operation: OpDecrypt, Connection: "app-local", Input: enc.Output, AAD: []byte("other")}); err == nil {
				t.Fatal("decrypt succeeded with the wrong AAD")
			}
		})
	}
}

func TestJWTVerifiesWithStandardLibrary(t *testing.T) {
	k := newTestKeys(t)
	claims := []byte(`{"sub":"release","iss":"keylatch"}`)
	cases := []struct {
		alg    string
		key    []byte
		verify any
	}{
		{HS256, k.hmac, k.hmac},
		{ES256, k.es256, k.es256Pub},
		{EdDSA, k.ed, k.edPub},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			s, cap := service(t, fullPolicy("k", []string{"jwt_sign"}, tc.alg), mapKeys{"k": tc.key})
			res, err := s.Do(context.Background(), human, Request{Operation: OpJWTSign, Connection: "app-local", Input: claims, KeyID: "k1"})
			if err != nil {
				t.Fatal(err)
			}
			method := map[string]jwt.SigningMethod{HS256: jwt.SigningMethodHS256, ES256: jwt.SigningMethodES256, EdDSA: jwt.SigningMethodEdDSA}[tc.alg]
			tok, err := jwt.Parse(string(res.Output), func(*jwt.Token) (any, error) { return tc.verify, nil },
				jwt.WithValidMethods([]string{tc.alg}), jwt.WithIssuer("keylatch"))
			if err != nil || !tok.Valid {
				t.Fatalf("token did not verify with the real key: %v", err)
			}
			if tok.Method != method || tok.Header["kid"] != "k1" {
				t.Fatalf("unexpected header: %v", tok.Header)
			}
			assertAbsent(t, cap.dump(), tc.key)
			assertAbsent(t, string(res.Output), tc.key)
		})
	}
}

func TestJWTRejectsNonObjectClaims(t *testing.T) {
	k := newTestKeys(t)
	s, _ := service(t, fullPolicy("k", []string{"jwt_sign"}, HS256), mapKeys{"k": k.hmac})
	for _, in := range []string{`"text"`, `[1]`, `not json`, ``} {
		if _, err := s.Do(context.Background(), human, Request{Operation: OpJWTSign, Connection: "app-local", Input: []byte(in)}); err == nil {
			t.Fatalf("claims %q were signed", in)
		}
	}
}

func TestAllowlistRefusals(t *testing.T) {
	k := newTestKeys(t)
	p := fullPolicy("k", []string{"sign"}, HS256)
	s, cap := service(t, p, mapKeys{"k": k.hmac})
	ctx := context.Background()

	for name, req := range map[string]Request{
		"operation not listed":    {Operation: OpVerify, Connection: "app-local", Alg: HS256, Input: []byte("x"), Signature: []byte("y")},
		"encrypt not listed":      {Operation: OpEncrypt, Connection: "app-local", Alg: A256GCM, Input: []byte("x")},
		"jwt not listed":          {Operation: OpJWTSign, Connection: "app-local", Alg: HS256, Input: []byte("{}")},
		"algorithm not listed":    {Operation: OpSign, Connection: "app-local", Alg: HS512, Input: []byte("x")},
		"alg of another family":   {Operation: OpSign, Connection: "app-local", Alg: ES256, Input: []byte("x")},
		"unknown algorithm alias": {Operation: OpSign, Connection: "app-local", Alg: "MD5", Input: []byte("x")},
	} {
		if _, err := s.Do(ctx, human, req); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: want a refusal, got %v", name, err)
		}
	}
	if _, err := s.Do(ctx, human, Request{Operation: OpSign, Connection: "elsewhere", Alg: HS256, Input: []byte("x")}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown connection: %v", err)
	}
	if _, err := s.Do(ctx, human, Request{Operation: OpSign, Connection: "app-local", Alg: HS256, Input: []byte("x")}); err != nil {
		t.Errorf("an allowed operation was refused: %v", err)
	}
	if !strings.Contains(cap.dump(), `"outcome":"denied"`) {
		t.Fatal("refusals are not audited")
	}
}

func TestDecryptForConstrainedCallers(t *testing.T) {
	k := newTestKeys(t)
	p := fullPolicy("k", []string{"encrypt", "decrypt"}, A256GCM)
	s, _ := service(t, p, mapKeys{"k": k.aes})
	enc, err := s.Do(context.Background(), agentCaller, Request{Operation: OpEncrypt, Connection: "app-local", Input: []byte("data")})
	if err != nil {
		t.Fatalf("encrypt for an agent: %v", err)
	}
	if _, err := s.Do(context.Background(), agentCaller, Request{Operation: OpDecrypt, Connection: "app-local", Input: enc.Output}); !errors.Is(err, ErrDenied) {
		t.Fatalf("agent decrypt should be refused by default: %v", err)
	}
	if _, err := s.Do(context.Background(), Caller{Kind: "host", Constrained: true}, Request{Operation: OpDecrypt, Connection: "app-local", Input: enc.Output}); !errors.Is(err, ErrDenied) {
		t.Fatalf("host decrypt should be refused by default: %v", err)
	}

	fp := p.conns["app-local"]["KEY"]
	fp.AgentDecrypt = true
	p.conns["app-local"]["KEY"] = fp
	if res, err := s.Do(context.Background(), agentCaller, Request{Operation: OpDecrypt, Connection: "app-local", Input: enc.Output}); err != nil || string(res.Output) != "data" {
		t.Fatalf("agent decrypt with the connection's consent: %q %v", res.Output, err)
	}
}

func TestKeyNeverInAuditOrErrors(t *testing.T) {
	k := newTestKeys(t)
	cases := []struct {
		alg string
		key []byte
		op  Operation
	}{
		{HS256, k.hmac, OpSign}, {EdDSA, k.ed, OpSign}, {ES256, k.es256, OpSign},
		{ES384, k.es384, OpSign}, {PS256, k.rsaKey, OpSign}, {A256GCM, k.aes, OpEncrypt},
	}
	for _, tc := range cases {
		s, cap := service(t, fullPolicy("k", []string{string(tc.op)}, tc.alg), mapKeys{"k": tc.key})
		in := []byte("input data " + tc.alg)
		res, err := s.Do(context.Background(), agentCaller, Request{Operation: tc.op, Connection: "app-local", Alg: tc.alg, Input: in})
		if err != nil {
			t.Fatalf("%s: %v", tc.alg, err)
		}
		dump := cap.dump()
		assertAbsent(t, dump+string(res.Output), tc.key)
		sum := sha256.Sum256(in)
		for _, want := range []string{`"operation":"` + string(tc.op) + `"`, `"alg":"` + tc.alg + `"`, `"connection":"app-local"`, `"caller_kind":"agent"`, hex.EncodeToString(sum[:])} {
			if !strings.Contains(dump, want) {
				t.Errorf("%s: audit event is missing %s: %s", tc.alg, want, dump)
			}
		}
		if strings.Contains(dump, string(in)) {
			t.Errorf("%s: audit event holds the input", tc.alg)
		}
	}

	s, _ := service(t, fullPolicy("k", []string{"sign"}, ES256), mapKeys{"k": k.ed})
	_, err := s.Do(context.Background(), human, Request{Operation: OpSign, Connection: "app-local", Alg: ES256, Input: []byte("x")})
	if err == nil {
		t.Fatal("a mismatched key type signed")
	}
	assertAbsent(t, err.Error(), k.ed)
}

func TestAuditFailureWithholdsResult(t *testing.T) {
	k := newTestKeys(t)
	s, cap := service(t, fullPolicy("k", []string{"sign"}, HS256), mapKeys{"k": k.hmac})
	cap.fail = true
	res, err := s.Do(context.Background(), human, Request{Operation: OpSign, Connection: "app-local", Alg: HS256, Input: []byte("x")})
	if !errors.Is(err, ErrUnavailable) || len(res.Output) != 0 {
		t.Fatalf("an operation that could not be audited returned a result: %v %x", err, res.Output)
	}
}

func TestNewRequiresAudit(t *testing.T) {
	if _, err := New(fullPolicy("k", nil), mapKeys{}, nil); err == nil {
		t.Fatal("a service without an audit emitter was created")
	}
}

func TestAuditEventShape(t *testing.T) {
	k := newTestKeys(t)
	s, cap := service(t, fullPolicy("k", []string{"sign"}, HS256), mapKeys{"k": k.hmac})
	if _, err := s.Do(context.Background(), human, Request{Operation: OpSign, Connection: "app-local", Input: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if len(cap.events) != 1 || cap.events[0].Action != audit.ActionKeyOperation || cap.events[0].Outcome != audit.OutcomeOK {
		t.Fatalf("unexpected events: %+v", cap.events)
	}
}
