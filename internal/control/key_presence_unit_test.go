//go:build !windows

package control

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/exitcode"
	"github.com/keylatch/keylatch/internal/keyops"
)

func TestKeyAllowSummaryShowsBeforeAndAdditions(t *testing.T) {
	kp := KeyPolicyRequest{Connection: "c", Field: "F", Operations: []string{"decrypt", "sign"}, HostKeys: []string{"SHA256:x"}, SSHAgent: true}

	fresh := keyAllowSummary(kp, nil)
	for _, want := range []string{"allow key operations on c field F", "before:   new entry", "adds:     operations decrypt,sign", "host keys SHA256:x", "secret:   unchanged"} {
		if !strings.Contains(fresh, want) {
			t.Errorf("summary lacks %q:\n%s", want, fresh)
		}
	}

	widened := keyAllowSummary(kp, &allowedEntry{Operations: []string{"encrypt"}, Algorithms: []string{"A256GCM"}, AgentDecrypt: true})
	if !strings.Contains(widened, "before:   operations encrypt; algorithms A256GCM; agent decrypt true; ssh-agent host keys 0") {
		t.Errorf("summary does not show the entry as it stands:\n%s", widened)
	}
}

// The daemon refuses an allow that carries no presence proof, whoever asks,
// and applies one that does.
func TestKeyPolicyAllowNeedsAProofFromAHuman(t *testing.T) {
	dir := t.TempDir()
	store := keyops.NewStore(filepath.Join(dir, "key-operations.json"), keyops.MACKey(bytes.Repeat([]byte{3}, 32)))
	rec := &recordedAudit{}
	admin, err := keyops.NewAdmin(store, rec)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(Config{KeyAdmin: admin})
	ask := KeyPolicyRequest{Action: "allow", Connection: "c", Field: "F", Secret: "s", Operations: []string{"sign"}}

	resp := srv.keyPolicy(t.Context(), KindHuman, &ask)
	if resp.OK || resp.ExitCode != exitcode.SecurityBlock {
		t.Fatalf("an allow without a proof was accepted: %+v", resp)
	}
	if doc, _ := store.Load(); len(doc) != 0 {
		t.Fatalf("the unproven allow was applied: %+v", doc)
	}

	ask.PresenceDigest = "digest-of-what-the-human-read"
	if resp = srv.keyPolicy(t.Context(), KindHuman, &ask); !resp.OK {
		t.Fatalf("an allow with a proof was refused: %+v", resp)
	}
	if !strings.Contains(rec.dump(), "digest-of-what-the-human-read") {
		t.Fatalf("the audit event lacks the presence proof: %s", rec.dump())
	}

	ask.Field = "G"
	if resp = srv.keyPolicy(t.Context(), KindAgent, &ask); resp.OK {
		t.Fatalf("an agent widened the allowlist with a borrowed proof: %+v", resp)
	}
}
