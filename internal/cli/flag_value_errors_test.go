package cli

import (
	"context"
	"strings"
	"testing"
)

// A value typed without its key=, for example a pasted token, must never be
// echoed back in an error: errors reach stderr and the agent's transcript.
const pastedSecret = "sk-pasted-without-key-4f1c"

func TestKeyValueFlagErrorsNeverEchoValues(t *testing.T) {
	checks := map[string]func() error{
		"--param": func() error {
			_, err := parseParamFlags([]string{"model=x", pastedSecret})
			return err
		},
		"--stdin-field": func() error {
			_, err := ResolveStdinFields([]string{pastedSecret})
			return err
		},
		"--provider-ref without =": func() error {
			return resolveProviderRefs(context.Background(), []string{pastedSecret}, map[string][]byte{})
		},
		"--provider-ref without field": func() error {
			return resolveProviderRefs(context.Background(), []string{"=" + pastedSecret}, map[string][]byte{})
		},
	}
	for name, run := range checks {
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), pastedSecret) {
				t.Fatalf("error echoes the flag value: %v", err)
			}
		})
	}
}
