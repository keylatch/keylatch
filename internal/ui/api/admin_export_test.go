package api

import "testing"

// EnableAdminConsole opens the build gate on the admin console for one test.
func EnableAdminConsole(t testing.TB) {
	t.Helper()
	prev := adminEnabled
	adminEnabled = func() bool { return true }
	t.Cleanup(func() { adminEnabled = prev })
}
