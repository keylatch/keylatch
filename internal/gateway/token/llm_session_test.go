package token_test

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/gateway/token"
)

// TestLLMSession_FIND001 verifies that two tokens identical except for LLMSession
// behave differently for read-class routes.
func TestLLMSession_ReadClassBlocked(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	storePath := testStorePath(t)

	readCaps := []string{"read", "export", "secrets.reveal", "data.dump"}

	for _, cap := range readCaps {
		t.Run(cap, func(t *testing.T) {
			// Non-LLM token with read-class cap.
			_, nonLLMTok, err := token.Mint(token.TokenSpec{
				Actor:        "actor",
				Capabilities: []string{cap},
				TTL:          1 * time.Hour,
				LLMSession:   false,
				SigningKey:   key,
				StorePath:    storePath,
			})
			if err != nil {
				t.Fatal(err)
			}

			// LLM token with same read-class cap.
			_, llmTok, err := token.Mint(token.TokenSpec{
				Actor:        "actor",
				Capabilities: []string{cap},
				TTL:          1 * time.Hour,
				LLMSession:   true,
				SigningKey:   key,
				StorePath:    storePath,
			})
			if err != nil {
				t.Fatal(err)
			}

			// Non-LLM token should have read-class cap.
			if !token.HasCapability(nonLLMTok, cap) {
				t.Errorf("non-LLM token should have capability %q", cap)
			}

			// LLM token should also have the cap in the token itself.
			if !token.HasCapability(llmTok, cap) {
				t.Errorf("LLM token should have capability %q (gate is at handler level)", cap)
			}

			// Verify LLMSession field is set correctly.
			if nonLLMTok.LLMSession {
				t.Error("non-LLM token should have LLMSession=false")
			}
			if !llmTok.LLMSession {
				t.Error("LLM token should have LLMSession=true")
			}

			// The handler-level gate is tested in handler_deny_test.go.
			// Here we just verify IsReadClassCap returns true for these caps.
			if !token.IsReadClassCap(cap) {
				t.Errorf("IsReadClassCap(%q) should be true", cap)
			}
		})
	}
}

func TestLLMSession_NonReadClassAllowed(t *testing.T) {
	// Verify non-read-class caps are not blocked by IsReadClassCap.
	nonReadCaps := []string{"chat_completion", "error_reporting", "gateway_call"}
	for _, cap := range nonReadCaps {
		if token.IsReadClassCap(cap) {
			t.Errorf("IsReadClassCap(%q) should be false", cap)
		}
	}
}

func TestLLMSession_JWTClaimPreserved(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	storePath := testStorePath(t)

	jwtStr, _, err := token.Mint(token.TokenSpec{
		Actor:        "llm-actor",
		Capabilities: []string{"chat.send"},
		TTL:          1 * time.Hour,
		LLMSession:   true,
		SigningKey:   key,
		StorePath:    storePath,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify retrieves the token with LLMSession=true from JWT claim.
	verified, err := token.Verify(jwtStr, nil, key, storePath)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.LLMSession {
		t.Error("LLMSession should be true after JWT round-trip")
	}
}
