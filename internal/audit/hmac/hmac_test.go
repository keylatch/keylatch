package hmac_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
)

type vector struct {
	Description    string `json:"description"`
	Key            string `json:"key"`
	Data           string `json:"data"`
	ExpectedSHA256 string `json:"expected_sha256"`
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func TestRFC4231Vectors(t *testing.T) {
	data, err := os.ReadFile("testdata/hmac-rfc4231.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse testdata: %v", err)
	}

	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			key := mustDecodeHex(t, v.Key)
			inputData := mustDecodeHex(t, v.Data)
			// expected_sha256 is the full 32-byte HMAC-SHA256; our Of() truncates to 16 bytes.
			expectedFull := mustDecodeHex(t, v.ExpectedSHA256)
			expectedTruncated := hex.EncodeToString(expectedFull[:16])

			got := audithmac.Of(key, inputData)
			if got != expectedTruncated {
				t.Errorf("got: %s\nwant: %s", got, expectedTruncated)
			}
		})
	}
}

func TestHMACDeterminism(t *testing.T) {
	salt := []byte("test-salt")
	data := []byte("test-data")

	first := audithmac.Of(salt, data)
	for i := 0; i < 1000; i++ {
		got := audithmac.Of(salt, data)
		if got != first {
			t.Fatalf("non-deterministic at iteration %d: %q vs %q", i, got, first)
		}
	}
}

func TestDifferentSaltProducesDifferentOutput(t *testing.T) {
	data := []byte("same data")
	h1 := audithmac.Of([]byte("salt1"), data)
	h2 := audithmac.Of([]byte("salt2"), data)
	if h1 == h2 {
		t.Error("different salts produced same HMAC output")
	}
}

func TestActorAccessorCommandHMAC(t *testing.T) {
	salt := []byte("test-salt")

	a := audithmac.ActorHMAC(salt, "user@example.com")
	b := audithmac.AccessorHMAC(salt, "accessor-id")
	c := audithmac.CommandHMAC(salt, []string{"keylatch", "get", "path"}, "/home/user")

	for _, h := range []string{a, b, c} {
		if len(h) != 32 {
			t.Errorf("HMAC output length = %d, want 32 hex chars", len(h))
		}
	}

	// Different inputs → different outputs.
	a2 := audithmac.ActorHMAC(salt, "other@example.com")
	if a == a2 {
		t.Error("different actors produced same HMAC")
	}
}
