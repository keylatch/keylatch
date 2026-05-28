package bootstrap

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RenderJSON encodes plan as compact JSON.
func RenderJSON(plan Plan) ([]byte, error) {
	b, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal plan: %w", err)
	}
	return b, nil
}

// RenderText formats plan as a human-readable list of steps.
func RenderText(plan Plan) string {
	var sb strings.Builder
	for _, s := range plan.Steps {
		switch s.Action {
		case "noop":
			fmt.Fprintf(&sb, "  [skip]  %s (%s)\n", s.Path, s.Reason)
		default:
			doneStr := "planned"
			if s.Done {
				doneStr = "done"
			}
			fmt.Fprintf(&sb, "  [%s] %s %s (mode %04o) — %s\n",
				doneStr, s.Action, s.Path, s.Mode, s.Reason)
		}
	}
	if len(plan.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range plan.Warnings {
			fmt.Fprintf(&sb, "  ! %s\n", w)
		}
	}
	return sb.String()
}
