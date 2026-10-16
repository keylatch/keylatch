// Package guard embeds the agent guard scripts shipped with keylatch.
// The embedded scripts are written to disk and wired into agent tool-call hooks
// by the `keylatch install-guard` command.
package guard

import _ "embed"

// GuardScript is the pre-tool-use hook script shared by every shell-hook
// harness; the hook command selects the payload and deny contract with
// --harness.
//
//go:embed scripts/block-keylatch-exfiltration.sh
var GuardScript []byte

// OpenCodeScript is the TypeScript plugin for OpenCode.
//
//go:embed scripts/opencode-guard.ts
var OpenCodeScript []byte
