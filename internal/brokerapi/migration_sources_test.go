package brokerapi

import (
	"bytes"
	"strings"
	"testing"
)

func TestMigrationSourcesAreReviewedAndBound(t *testing.T) {
	req := Request{Op: OpMigrateSources, Nonce: bytes.Repeat([]byte{1}, 32), Items: []Item{
		{Path: "app/token", Source: "env:/project/.env#API_TOKEN", Value: []byte("never-display-this-value")},
		{Path: "app/other\npath", Source: "pm:op:Vault/Item/field\u202e", Value: []byte("other-value")},
	}}
	if _, err := Decode(frame(t, req)); err != nil {
		t.Fatal(err)
	}
	if !Privileged(req.Op) {
		t.Fatal("source import must require presence")
	}
	action, summary := req.Describe()
	if action != "migrate.import" || !strings.Contains(summary, "env:/project/.env#API_TOKEN") || !strings.Contains(summary, "app/token") {
		t.Fatalf("missing migration review: %s %s", action, summary)
	}
	if strings.Contains(summary, "never-display-this-value") || strings.Contains(summary, "other-value") || strings.ContainsRune(summary, '\u202e') || strings.Contains(summary, "other\npath") {
		t.Fatalf("unsafe migration review: %s", summary)
	}
	if !strings.Contains(summary, `\u202e`) || !strings.Contains(summary, `other\npath`) {
		t.Fatal("control characters were hidden instead of escaped")
	}
	digest := req.Digest()
	req.Items[0].Source = "env:/different/.env#API_TOKEN"
	if req.Digest() == digest {
		t.Fatal("source change reused the approved digest")
	}
	legacy := req
	legacy.Op = OpMigrateImport
	if legacy.Digest() == req.Digest() {
		t.Fatal("migration proof applies to adoption")
	}
	if legacy.Validate() == nil {
		t.Fatal("adoption accepted unbound source references")
	}
}

func TestMigrationSourcesRequireEveryReference(t *testing.T) {
	for _, source := range []string{"", "bad\x00ref", strings.Repeat("x", 2049)} {
		req := Request{Op: OpMigrateSources, Nonce: make([]byte, 32), Items: []Item{{Path: "app/key", Source: source, Value: []byte("value")}}}
		if req.Validate() == nil {
			t.Fatal("invalid source reference accepted")
		}
	}
}

func TestMigrationReviewDoesNotHideLaterItems(t *testing.T) {
	req := Request{Op: OpMigrateSources}
	for i := range 30 {
		label := strings.Repeat("x", i+1)
		req.Items = append(req.Items, Item{Path: "destination/" + label, Source: "source:" + label})
	}
	_, summary := req.Describe()
	if strings.Count(summary, "\nSource ") != len(req.Items) {
		t.Fatal("migration review hid source/destination pairs")
	}
}
