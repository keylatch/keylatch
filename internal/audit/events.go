package audit

// Brokered-action events. Each action Keylatch performs on a caller's behalf
// writes exactly one of these; the fields an event may carry are allowlisted
// in audit/fields and never include a value, a key or a token.
const (
	// ActionRun records one command run through a runtime: connection,
	// runtime, capability, caller kind, the policy decision, exit status and
	// duration.
	ActionRun Action = "run"
	// ActionCall records one `keylatch call` action against a connection.
	ActionCall Action = "call"

	// ActionMint records one scoped credential mint. Extra holds the
	// connection, repository, permissions, expires_at and caller kind;
	// the minted credential is never recorded.
	ActionMint Action = "mint"
	// ActionRelease records a secret value handed to a caller outside
	// Keylatch (get, export). Extra names the connection and field, never the
	// value.
	ActionRelease Action = "release"

	// ActionConnect records a connection created or updated, and ActionSet a
	// secret field written. Both carry names only.
	ActionConnect Action = "connect"
	ActionSet     Action = "set"

	// ActionPolicyChange records an edit to grants, allow or deny rules, or
	// policy files, including refused attempts.
	ActionPolicyChange Action = "policy.change"
	// ActionPresenceDecision records a human-presence check and its outcome.
	ActionPresenceDecision Action = "presence.decision"

	// ActionSecurityBlock records a request refused because the caller is an
	// LLM session; ActionGuardBlock records a command the agent guard hook
	// refused. Both carry the command's name and the signals, never its
	// arguments.
	ActionSecurityBlock Action = "security.block"
	ActionGuardBlock    Action = "guard.block"

	// ActionBackupExport records a backup written.
	ActionBackupExport Action = "backup.export"

	// ActionRunDecided records the daemon's decision on a socket request that
	// runs something: tier, where the child runs, caller kind and harness,
	// digests of argv and cwd, and the hosts involved. Allows and refusals
	// both produce one event.
	ActionRunDecided Action = "run.decided"
	// ActionRunExited records the end of a decided run: exit status, duration
	// and bytes relayed.
	ActionRunExited Action = "run.exited"
	// ActionApprovalRequested, ActionApprovalGranted and ActionApprovalDenied
	// record the life of an approval a decision waited on. Extra carries the
	// approval id and the run it belongs to, never the approval's proof.
	ActionApprovalRequested Action = "approval.requested"
	ActionApprovalGranted   Action = "approval.granted"
	ActionApprovalDenied    Action = "approval.denied"

	// binding change actions. Extra holds the connection, caller kind and the
	// before/after host sets.
	ActionBindingCreated  Action = "binding.created"
	ActionBindingWidened  Action = "binding.widened"
	ActionBindingNarrowed Action = "binding.narrowed"
	ActionBindingRefused  Action = "binding.refused"
)
