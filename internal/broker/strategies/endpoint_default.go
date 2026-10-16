//go:build !mint_test_endpoint

package strategies

// apiBaseOverride is the API root a conformance test build takes from the
// environment. The default build has none: no variable can redirect the
// GitHub App key or the tokens it mints to another host.
func apiBaseOverride() string { return "" }
