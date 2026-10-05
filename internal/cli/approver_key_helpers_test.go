package cli

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"slices"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
	"github.com/keylatch/keylatch/internal/gateway/approval"
)

const testApproverPassphrase = "correct horse battery"

// testDecisionKey signs decisions made through the approval package
// directly; it is unrelated to any configured approver key.
var testDecisionKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// withApprover configures an approver key in a fresh config dir and answers
// every hidden prompt with its passphrase. It returns the approver public
// key.
func withApprover(t *testing.T) ed25519.PublicKey {
	t.Helper()
	withCheapApproverKDF(t)
	configDir := t.TempDir()
	t.Setenv("KEYLATCH_CONFIG_DIR", configDir)
	key, _, err := approval.NewApproverKey([]byte(testApproverPassphrase), approverKDFParams)
	if err != nil {
		t.Fatal(err)
	}
	if err := approval.SaveApproverKey(filepath.Join(configDir, "approver.json"), key); err != nil {
		t.Fatal(err)
	}
	withHiddenAnswers(t, testApproverPassphrase)
	pub, err := key.Public()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func withCheapApproverKDF(t *testing.T) {
	t.Helper()
	prev := approverKDFParams
	approverKDFParams = argon2.Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}
	t.Cleanup(func() { approverKDFParams = prev })
}

// withHiddenAnswers answers hidden prompts with answers in order, repeating
// the last one.
func withHiddenAnswers(t *testing.T, answers ...string) {
	t.Helper()
	prev := promptHiddenFn
	i := 0
	promptHiddenFn = func() ([]byte, error) {
		a := answers[min(i, len(answers)-1)]
		i++
		return slices.Clone([]byte(a)), nil
	}
	t.Cleanup(func() { promptHiddenFn = prev })
}

// shownOf returns the digest of the record as a reviewer would see it, or
// "" when it cannot be read.
func shownOf(t *testing.T, dir, token string) string {
	t.Helper()
	ar, err := approval.Get(context.Background(), dir, token)
	if err != nil {
		return ""
	}
	return approval.Digest(ar)
}
