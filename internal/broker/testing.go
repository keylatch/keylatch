//go:build !production

package broker

// ResetInProcessSingleton clears the in-process broker singleton.
// This is intended for use in tests that need a clean slate between
// sub-tests that call NewBroker. Call via t.Cleanup to restore the
// original state after each test.
//
// Only compiled when the "production" build tag is absent (i.e., during
// testing). Production binaries are built with -tags production.
func ResetInProcessSingleton() {
	inProcessMarker.Store(0)
	currentBrokerPtr.Store(nil)
}
