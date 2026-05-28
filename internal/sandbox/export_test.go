//go:build darwin

package sandbox

// GenerateSbProfileForTest exposes generateSbProfile for white-box testing.
func GenerateSbProfileForTest(m *SandboxManifest) (string, error) {
	return generateSbProfile(m)
}

// BuildSandboxExecArgsForTest exposes buildSandboxExecArgs for white-box testing.
func BuildSandboxExecArgsForTest(sbPath string, m *SandboxManifest, extraEnv []string) ([]string, error) {
	return buildSandboxExecArgs(sbPath, m, extraEnv)
}

// IndexOfForTest exposes indexOf for white-box testing.
func IndexOfForTest(s string, c byte) int {
	return indexOf(s, c)
}
