package token_test

import (
	"crypto/rand"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/gateway/token"
)

func TestTokenCarriesCallerKind(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	storePath := testStorePath(t)

	for _, tc := range []struct {
		caller callerkind.Kind
		llm    bool
	}{
		{callerkind.Agent, true},
		{callerkind.Host, false},
		{callerkind.Human, false},
		{callerkind.Service, false},
	} {
		jwt, minted, err := token.Mint(token.TokenSpec{Actor: "a", Capabilities: []string{"x.y"}, TTL: time.Hour, Caller: tc.caller, SigningKey: key, StorePath: storePath})
		if err != nil {
			t.Fatal(err)
		}
		if minted.CallerKind != tc.caller || minted.LLMSession != tc.llm {
			t.Errorf("%s: minted kind=%q llm=%v", tc.caller, minted.CallerKind, minted.LLMSession)
		}
		got, err := token.Verify(jwt, nil, key, storePath)
		if err != nil {
			t.Fatal(err)
		}
		if got.CallerKind != tc.caller || got.LLMSession != tc.llm {
			t.Errorf("%s: verified kind=%q llm=%v", tc.caller, got.CallerKind, got.LLMSession)
		}
	}
}

// Editing the stored record cannot turn an agent token into anything else:
// the signed claims restore the restriction.
func TestStoreEditCannotRelaxAnAgentToken(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	storePath := testStorePath(t)

	jwt, _, err := token.Mint(token.TokenSpec{Actor: "a", Capabilities: []string{"x.y"}, TTL: time.Hour, Caller: callerkind.Agent, SigningKey: key, StorePath: storePath})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	if err := json.Unmarshal(data, &records); err != nil {
		t.Fatal(err)
	}
	records[0]["caller_kind"] = "human"
	records[0]["llm_session"] = false
	edited, _ := json.Marshal(records)
	if err := os.WriteFile(storePath, edited, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := token.Verify(jwt, nil, key, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if got.CallerKind != callerkind.Agent || !got.LLMSession {
		t.Fatalf("edited record relaxed the token: kind=%q llm=%v", got.CallerKind, got.LLMSession)
	}
}

// A token minted before tokens carried a kind stays an LLM-session token when
// it was one.
func TestLegacyLLMSessionTokenStaysRestricted(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	storePath := testStorePath(t)

	jwt, _, err := token.Mint(token.TokenSpec{Actor: "a", Capabilities: []string{"x.y"}, TTL: time.Hour, LLMSession: true, SigningKey: key, StorePath: storePath})
	if err != nil {
		t.Fatal(err)
	}
	got, err := token.Verify(jwt, nil, key, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LLMSession || got.CallerKind != "" {
		t.Fatalf("kind=%q llm=%v", got.CallerKind, got.LLMSession)
	}
}
