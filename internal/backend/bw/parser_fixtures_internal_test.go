package bw

// parser_fixtures_internal_test.go — M4: table-driven tests for isLocked and
// isNotFound against realistic bw CLI stderr transcripts, so a CLI-output
// wording change fails a unit test instead of silently breaking error
// classification for users.
//
// Each fixture's provenance is documented on the case: "observed" means the
// exact string has been seen from a real bw CLI invocation (2024-2026 era,
// npm @bitwarden/cli); "plausible variant" means it was constructed to
// exercise a wording/formatting variant the matcher SHOULD also handle
// (extra whitespace, leading log noise, combined sentences) but that hasn't
// been directly observed on this machine.

import "testing"

func TestIsLocked_Fixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		// --- observed ---
		{
			name:   "observed: locked vault, plain data op (bw get/list)",
			stderr: "Vault is locked.",
			want:   true,
		},
		{
			name:   "observed: not logged in at all (no account)",
			stderr: "You are not logged in.",
			want:   true,
		},
		{
			name:   "observed: bad/expired BW_SESSION on a data op",
			stderr: "Session key is invalid.",
			want:   true,
		},

		// --- plausible variants (not directly observed, matcher must still handle) ---
		{
			name:   "plausible: session-invalid combined with password hint",
			stderr: "Session key is invalid, or your master password is incorrect. Try again.",
			want:   true,
		},
		{
			name:   "plausible: leading timestamped debug noise before the real error",
			stderr: "[2026-01-15T10:22:31.000Z] DEBUG checking session state\nVault is locked.\n",
			want:   true,
		},
		{
			name:   "plausible: mixed-case wording from a future CLI revision",
			stderr: "VAULT IS LOCKED.",
			want:   true,
		},
		{
			name:   "plausible: not-logged-in with trailing guidance sentence",
			stderr: "You are not logged in. Run `bw login` to log in to Bitwarden.",
			want:   true,
		},

		// --- must NOT be classified as locked ---
		{
			name:   "must not match: item not found",
			stderr: "Not found.",
			want:   false,
		},
		{
			name:   "must not match: empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "must not match: unrelated permission error",
			stderr: "You do not have permission to view this item.",
			want:   false,
		},
		{
			name:   "must not match: generic sync failure unrelated to session state",
			stderr: "Syncing failed: could not connect to server.",
			want:   false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isLocked(tc.stderr); got != tc.want {
				t.Errorf("isLocked(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}

func TestIsNotFound_Fixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		// --- observed ---
		{
			name:   "observed: bw get item <bad-id>",
			stderr: "Not found.",
			want:   true,
		},

		// --- plausible variants ---
		{
			name:   "plausible: no items match a search filter",
			stderr: "No items found.",
			want:   true,
		},
		{
			name:   "plausible: mixed case from a future CLI revision",
			stderr: "NOT FOUND.",
			want:   true,
		},
		{
			name:   "plausible: not-found with surrounding context sentence",
			stderr: "Item not found. Check the ID and try again.",
			want:   true,
		},

		// --- must NOT be classified as not-found ---
		{
			name:   "must not match: locked vault",
			stderr: "Vault is locked.",
			want:   false,
		},
		{
			name:   "must not match: empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "must not match: not-logged-in (different remediation than not-found)",
			stderr: "You are not logged in.",
			want:   false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isNotFound(tc.stderr); got != tc.want {
				t.Errorf("isNotFound(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}
