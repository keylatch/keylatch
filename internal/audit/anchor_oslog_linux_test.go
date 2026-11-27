package audit

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The journald datagram names the keylatch-audit identifier and carries the
// head's number, hash and key id.
func TestOSLogAnchorJournaldDatagram(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "journal.sock")
	srv, err := net.ListenPacket("unixgram", sock)
	if err != nil {
		t.Skipf("cannot listen on a unix datagram socket here: %v", err)
	}
	defer srv.Close() //nolint:errcheck // test listener
	old := journalSocket
	journalSocket = sock
	t.Cleanup(func() { journalSocket = old })

	head := Head{Seq: 1000, Hash: "0123456789abcdef0123456789abcdef", Time: time.Now(), KeyID: "feedfacefeedface"}
	if err := OSLogAnchor(head); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	_ = srv.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := srv.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	got := string(buf[:n])
	for _, want := range []string{"SYSLOG_IDENTIFIER=keylatch-audit\n", "KEYLATCH_AUDIT_SEQ=1000\n", "KEYLATCH_AUDIT_HASH=" + head.Hash + "\n", "KEYLATCH_AUDIT_KEY_ID=" + head.KeyID + "\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("datagram %q lacks %q", got, want)
		}
	}
}
