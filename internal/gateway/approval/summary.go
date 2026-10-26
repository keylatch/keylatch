package approval

import (
	"fmt"
	"strings"
	"unicode"
)

// Summary is the exact request description shown by trusted presence prompts.
func Summary(ar *ApprovalRequest) string {
	if ar.Plan != "" {
		lines := strings.Split(ar.Plan, "\n")
		for i := range lines {
			lines[i] = DisplaySafe(lines[i])
		}
		return strings.TrimRight(strings.Join(lines, "\n"), "\n") + "\nrequest hash: " + DisplaySafe(ar.RequestHash)
	}
	return fmt.Sprintf("%s on %s for %s; request hash: %s", DisplaySafe(ar.Capability), DisplaySafe(ar.Connection), DisplaySafe(ar.Actor), DisplaySafe(ar.RequestHash))
}

// DisplaySafe removes controls and directional overrides from requester-written text.
func DisplaySafe(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, value)
}
