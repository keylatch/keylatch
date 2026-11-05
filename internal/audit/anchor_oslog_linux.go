package audit

import (
	"fmt"
	"net"
	"time"
)

// journalSocket is where journald listens for native-protocol datagrams.
var journalSocket = "/run/systemd/journal/socket"

// OSLogAnchor writes h to journald with SYSLOG_IDENTIFIER=keylatch-audit.
func OSLogAnchor(h Head) error {
	conn, err := net.DialTimeout("unixgram", journalSocket, 2*time.Second)
	if err != nil {
		return fmt.Errorf("audit anchor: journald: %w", err)
	}
	defer conn.Close() //nolint:errcheck // datagram socket
	msg := fmt.Sprintf("SYSLOG_IDENTIFIER=%s\nPRIORITY=6\nMESSAGE=%s\nKEYLATCH_AUDIT_SEQ=%d\nKEYLATCH_AUDIT_HASH=%s\nKEYLATCH_AUDIT_KEY_ID=%s\n",
		anchorIdentifier, anchorMessage(h), h.Seq, h.Hash, h.KeyID)
	if _, err := conn.Write([]byte(msg)); err != nil {
		return fmt.Errorf("audit anchor: journald: %w", err)
	}
	return nil
}
