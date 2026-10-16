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

	// ActionBrokerAdopt records secrets moved from a user's own store into the
	// broker, and ActionBrokerExport records the reverse. Both carry counts;
	// adopt also carries the head of the in-user audit chain it replaces.
	ActionBrokerAdopt  Action = "broker.adopt"
	ActionBrokerExport Action = "broker.export"

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

	// ActionContainedLeakSuspected records a secret value, or an encoding of
	// it, found in files a contained run wrote. Extra carries the run id, the
	// connection, the caller kind and the number of files; never a path
	// content or the value.
	ActionContainedLeakSuspected Action = "contained.leak_suspected"
	// ActionSandboxDegraded records a run that started with part of the
	// sandbox missing, for example without cgroup limits.
	ActionSandboxDegraded Action = "sandbox.degraded"
	// ActionCanaryTripped records a canary value seen where it must not be.
	// Extra carries the session, the host and where it was seen; never the
	// canary itself.
	ActionCanaryTripped Action = "canary.tripped"

	// binding change actions. Extra holds the connection, caller kind and the
	// before/after host sets.
	ActionBindingCreated  Action = "binding.created"
	ActionBindingWidened  Action = "binding.widened"
	ActionBindingNarrowed Action = "binding.narrowed"
	ActionBindingRefused  Action = "binding.refused"
)

// Deploy-secret sync, service credential and machine credential events. None
// carries a value or a hash of one.
const (
	ActionSyncWrite          Action = "sync.write"
	ActionSyncDelete         Action = "sync.delete"
	ActionSyncRotateVerify   Action = "sync.rotate.verify"
	ActionSyncRotateRollback Action = "sync.rotate.rollback"
	ActionSyncRotateComplete Action = "sync.rotate.complete"
	ActionServiceEnroll      Action = "service.enroll"
	ActionServiceRevoke      Action = "service.revoke"
	ActionMachineIssue       Action = "machine.issue"
	ActionMachineRevoke      Action = "machine.revoke"
)
