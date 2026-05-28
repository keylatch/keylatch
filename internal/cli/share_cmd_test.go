package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/cli"
)

func TestShareCmd_PublicFlag_Cancelled(t *testing.T) {
	root := cli.NewRootCommand()

	var stdout, stderr bytes.Buffer
	// Provide "N" as stdin to cancel the confirmation prompt.
	root.SetIn(strings.NewReader("N\n"))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"share", "--public", "some-receipt-id"})

	if err := root.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := stdout.String()
	if !strings.Contains(out, "Cancelled") {
		t.Errorf("expected output to mention Cancelled, got: %q", out)
	}
}

func TestShareCmd_PublicFlag_Prompt(t *testing.T) {
	root := cli.NewRootCommand()

	var stdout, stderr bytes.Buffer
	// Provide "N" to cancel — avoids making a real HTTP call in unit tests.
	root.SetIn(strings.NewReader("N\n"))
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"share", "--public", "some-receipt-id"})

	_ = root.Execute()

	out := stdout.String()
	if !strings.Contains(out, "sanitised summary publicly") {
		t.Errorf("expected confirmation prompt in output, got: %q", out)
	}
}

func TestShareCmd_StubMessage(t *testing.T) {
	root := cli.NewRootCommand()

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"share", "some-receipt-id"})

	// The command exits without error — it prints a stub message to stderr.
	_ = root.Execute()

	errOut := stderr.String()
	if !strings.Contains(errOut, "in-memory") {
		t.Errorf("expected stderr to mention in-memory receipts, got: %q", errOut)
	}
}
