package audit

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// OSLogAnchor writes h to the unified log (os_log) through logger(1), tagged
// keylatch-audit.
func OSLogAnchor(h Head) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: fixed binary; the arguments are the anchor's number, hash and key id.
	out, err := exec.CommandContext(ctx, "/usr/bin/logger", "-t", anchorIdentifier, "-p", "user.notice", anchorMessage(h)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("audit anchor: os_log: %w: %s", err, out)
	}
	return nil
}
