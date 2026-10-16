package doctor

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/keyops"
	"github.com/keylatch/keylatch/internal/llmcontext"
)

// checkKeyOperations verifies the key operation allowlist's integrity seal.
func checkKeyOperations(env llmcontext.Lookup) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "daemon.key_operations", Section: "daemon", Tags: []string{"key-operations"}}
		keys, present, err := keyops.Inspect(env)
		switch {
		case errors.Is(err, keyops.ErrTampered):
			st.Detail = err.Error()
			st.Fix = "Restore the allowlist from a backup, or remove it and re-add entries with `keylatch key allow`."
		case err != nil:
			st.Warn, st.OK = true, true
			st.Detail = fmt.Sprintf("key operation allowlist could not be read: %v", err)
		case !present:
			st.OK, st.Detail = true, "no key operation allowlist (optional)"
		default:
			st.OK, st.Detail = true, fmt.Sprintf("key operation allowlist verified (%d keys)", keys)
		}
		return st
	}
}
