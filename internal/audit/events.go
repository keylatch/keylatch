package audit

// Events for privileged actions and policy changes. Their allowlisted fields
// live in internal/audit/fields and never include values.
const (
	// ActionPresenceDecision records a human approval or refusal. Extra holds
	// the gated action, the method, the digest of what the human read and the
	// outcome reason.
	ActionPresenceDecision Action = "presence.decision"
	// ActionPolicyChange records a change to connection policy: what changed,
	// for which connection and the digest of the approved summary.
	ActionPolicyChange Action = "policy.change"
	// ActionBackupExport records an encrypted backup export. Extra holds the
	// item count; never an item, a path inside the vault or the passphrase.
	ActionBackupExport Action = "backup.export"
)
