package audit

import (
	"fmt"

	"golang.org/x/sys/windows/svc/eventlog"
)

// OSLogAnchor writes h to the Windows Event Log under the keylatch-audit
// source, registering the source on first use when the process may.
func OSLogAnchor(h Head) error {
	l, err := eventlog.Open(anchorIdentifier)
	if err != nil {
		if ierr := eventlog.InstallAsEventCreate(anchorIdentifier, eventlog.Info); ierr != nil {
			return fmt.Errorf("audit anchor: event log source: %w", err)
		}
		if l, err = eventlog.Open(anchorIdentifier); err != nil {
			return fmt.Errorf("audit anchor: event log: %w", err)
		}
	}
	defer l.Close() //nolint:errcheck // event log handle
	if err := l.Info(1, anchorMessage(h)); err != nil {
		return fmt.Errorf("audit anchor: event log: %w", err)
	}
	return nil
}
