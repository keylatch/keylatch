//go:build !sync_test_endpoint

package targets

// apiBase is the API root of a service. The default build has no override:
// no variable can redirect a target credential or the values written with it
// to another host.
func apiBase(_, def string) string { return def }
