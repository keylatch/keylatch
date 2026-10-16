package cli

// Tests that run the setup and bootstrap commands have no OS keyring and no
// terminal, so the operator's config is taken to allow a plaintext vault key.
// Tests of the refusal replace this.
func init() {
	insecureFileKEKAllowed = func() bool { return true }
}
