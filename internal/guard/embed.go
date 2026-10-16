// Package guard installs the agent exfiltration guard. The guard itself is the
// Go decider in internal/guard/hook, which each harness runs as
// `keylatch guard hook --harness <id>`; internal/harness knows where every
// harness keeps its hook, MCP and rules files. The shell script embedded here
// is the standalone variant under contrib/agent-guards: the installers read the
// credential locations it protects, and Claude Code's uninstall removes the
// copies earlier releases wrote.
package guard

import _ "embed"

// GuardScript is the shell variant of the guard; the hook command selects the
// payload and deny contract with --harness.
//
//go:embed scripts/block-keylatch-exfiltration.sh
var GuardScript []byte
