package op

// parser_fixtures_internal_test.go — M4: table-driven tests for
// isAuthFailure, isNotFound, and isAmbiguous against realistic 1Password CLI
// stderr transcripts, so a CLI-output wording change fails a unit test
// instead of silently breaking error classification for users.
//
// Each fixture's provenance is documented on the case: "observed" means the
// exact string (or the string from an existing testdata fixture already in
// this package) has been seen from a real op CLI invocation (2024-2026 era,
// op-cli v2); "plausible variant" means it was constructed to exercise a
// wording/formatting variant the matcher SHOULD also handle (op's real CLI
// prefixes most errors with "[ERROR] <timestamp> ") but that hasn't been
// directly observed on this machine.

import "testing"

func TestIsAuthFailure_Fixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		// --- observed (see testdata/auth_failure_stderr.txt, testdata/adversarial_stderr_service_account.txt) ---
		{
			name:   "observed: not signed in to any account",
			stderr: "not currently signed in to any 1Password account",
			want:   true,
		},
		{
			name:   "observed: invalid service account token",
			stderr: "authentication failed: invalid service account token",
			want:   true,
		},

		// --- plausible variants (real op CLI wraps errors with "[ERROR] <ts>") ---
		{
			name:   "plausible: full op-cli v2 [ERROR]-prefixed transcript, not signed in",
			stderr: "[ERROR] 2026/01/15 10:22:31 You are not currently signed in. Please run `op signin --help` for instructions",
			want:   true,
		},
		{
			name:   "plausible: session expired mid-command",
			stderr: "[ERROR] 2026/01/15 10:22:31 session expired, please sign in again",
			want:   true,
		},
		{
			name:   "plausible: authentication required for this vault",
			stderr: "[ERROR] 2026/01/15 10:22:31 authentication required to access this item",
			want:   true,
		},
		{
			name:   "plausible: generic authenticating failure wrapper",
			stderr: "[ERROR] 2026/01/15 10:22:31 error authenticating: dial tcp: connection refused",
			want:   true,
		},
		{
			name:   "plausible: mixed-case wording from a future CLI revision",
			stderr: "[ERROR] NOT CURRENTLY SIGNED IN.",
			want:   true,
		},

		// --- must NOT be classified as an auth failure ---
		{
			name:   "must not match: item not found",
			stderr: `[ERROR] 2026/01/15 10:22:31 "openrouter" isn't an item in the "Keylatch" vault. Specify the item with its UUID, or by exact name.`,
			want:   false,
		},
		{
			name:   "must not match: empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "must not match: ambiguous multi-item match",
			stderr: `[ERROR] 2026/01/15 10:22:31 More than one item matches "openrouter". Try again with the item's ID.`,
			want:   false,
		},
		{
			name:   "must not match: network-layer failure unrelated to auth",
			stderr: "[ERROR] 2026/01/15 10:22:31 dial tcp: lookup my.1password.com: no such host",
			want:   false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isAuthFailure(tc.stderr); got != tc.want {
				t.Errorf("isAuthFailure(%q) = %v, want %v", tc.stderr, got, tc.want)
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
		// --- observed-style (matches op-cli v2's real vault-scoped not-found wording) ---
		{
			name:   "observed: item not in the named vault",
			stderr: `[ERROR] 2026/01/15 10:22:31 "openrouter" isn't an item in the "Keylatch" vault. Specify the item with its UUID, or by exact name.`,
			want:   true,
		},

		// --- plausible variants ---
		{
			name:   "plausible: isn't an item in vault (no article)",
			stderr: `[ERROR] 2026/01/15 10:22:31 "openrouter" isn't an item in vault "Keylatch".`,
			want:   true,
		},
		{
			name:   "plausible: generic item-not-found wording",
			stderr: "[ERROR] 2026/01/15 10:22:31 item not found",
			want:   true,
		},
		{
			name:   "plausible: could-not-find-item wording (older op-cli v1 style)",
			stderr: "[ERROR] could not find item \"openrouter\"",
			want:   true,
		},

		// --- must NOT be classified as not-found ---
		{
			name:   "must not match: auth failure",
			stderr: "not currently signed in to any 1Password account",
			want:   false,
		},
		{
			name:   "must not match: empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "must not match: ambiguous multi-item match",
			stderr: `[ERROR] 2026/01/15 10:22:31 More than one item matches "openrouter". Try again with the item's ID.`,
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

func TestIsAmbiguous_Fixtures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		stderr string
		want   bool
	}{
		// --- observed-style ---
		{
			name:   "observed: more than one item matches",
			stderr: `[ERROR] 2026/01/15 10:22:31 More than one item matches "openrouter". Try again with the item's ID.`,
			want:   true,
		},

		// --- plausible variants ---
		{
			name:   "plausible: multiple items found wording",
			stderr: "[ERROR] multiple items found matching that name",
			want:   true,
		},
		{
			name:   "plausible: mixed-case wording from a future CLI revision",
			stderr: "[ERROR] MORE THAN ONE ITEM matches the query.",
			want:   true,
		},

		// --- must NOT be classified as ambiguous ---
		{
			name:   "must not match: not found",
			stderr: `[ERROR] 2026/01/15 10:22:31 "openrouter" isn't an item in the "Keylatch" vault.`,
			want:   false,
		},
		{
			name:   "must not match: empty stderr",
			stderr: "",
			want:   false,
		},
		{
			name:   "must not match: auth failure",
			stderr: "not currently signed in to any 1Password account",
			want:   false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isAmbiguous(tc.stderr); got != tc.want {
				t.Errorf("isAmbiguous(%q) = %v, want %v", tc.stderr, got, tc.want)
			}
		})
	}
}
