//go:build !windows

package control

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/presence/presencetest"
)

var allowSeed = []keyops.Change{{Connection: "app-local", Field: "DATA_KEY", Secret: "aes", Operations: []string{"encrypt"}, Algorithms: []string{"A256GCM"}}}

func listAllowlist(t *testing.T, d *keyDaemon) string {
	t.Helper()
	code, out, errOut := runKeyCLI(t, d.env, "", "key", "list", "app-local")
	if code != 0 {
		t.Fatalf("key list: exit %d %q", code, errOut)
	}
	return out
}

func TestKeyAllowNeedsPresence(t *testing.T) {
	d := startKeyDaemon(t, allowSeed, memoryKeys{"aes": bytes.Repeat([]byte{1}, 32)})
	allow := []string{"key", "allow", "app-local", "--field", "DATA_KEY", "--op", "decrypt"}
	before := listAllowlist(t, d)

	presencetest.NoTerminal(t)
	code, _, errOut := runKeyCLI(t, d.env, "", allow...)
	if code != exitcode.SecurityBlock || !strings.Contains(errOut, "needs a human") {
		t.Fatalf("without a terminal: exit %d %q", code, errOut)
	}
	presencetest.Decline(t)
	if code, _, _ = runKeyCLI(t, d.env, "", allow...); code != exitcode.SecurityBlock {
		t.Fatalf("declined: exit %d", code)
	}
	if got := listAllowlist(t, d); got != before {
		t.Fatalf("a refused change altered the allowlist:\n%s", got)
	}

	seen := presencetest.Record(t)
	if code, _, errOut = runKeyCLI(t, d.env, "", allow...); code != 0 {
		t.Fatalf("approved: exit %d %q", code, errOut)
	}
	if len(*seen) != 1 || !strings.Contains((*seen)[0], "key.allow") || !strings.Contains((*seen)[0], "before:   operations encrypt; algorithms A256GCM") || !strings.Contains((*seen)[0], "adds:     operations decrypt") {
		t.Fatalf("the prompt did not show the entry before and the additions: %q", *seen)
	}
	if !strings.Contains(listAllowlist(t, d), "decrypt") {
		t.Fatal("the approved change was not applied")
	}
	if !strings.Contains(d.audit.dump(), `"presence_digest"`) {
		t.Fatalf("the audit event does not carry the presence proof: %s", d.audit.dump())
	}
}

func TestKeyAllowWithoutProofIsRefusedForAHuman(t *testing.T) {
	d := startKeyDaemon(t, allowSeed, memoryKeys{"aes": bytes.Repeat([]byte{1}, 32)})
	c, err := NewClient(lookupOf(d.env))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.KeyPolicy(KeyPolicyRequest{Action: "allow", Connection: "app-local", Field: "DATA_KEY", Operations: []string{"decrypt"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK || resp.ExitCode != exitcode.SecurityBlock {
		t.Fatalf("a widening that carries no presence proof was accepted: %+v", resp)
	}
	if strings.Contains(listAllowlist(t, d), "decrypt") {
		t.Fatal("the unproven change was applied")
	}
}
