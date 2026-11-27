package audit

import "fmt"

// anchorIdentifier is the syslog identifier, event source and subsystem name
// anchors are written under, so they can be found with `journalctl -t
// keylatch-audit`, `log show --predicate 'senderImagePath ENDSWITH
// "keylatch-audit"'` or the Windows Event Viewer.
const anchorIdentifier = "keylatch-audit"

// anchorMessage is the line written to the OS log for one head. It holds the
// sequence number, hash and key id only.
func anchorMessage(h Head) string {
	return fmt.Sprintf("audit head seq=%d hash=%s key_id=%s", h.Seq, h.Hash, h.KeyID)
}
