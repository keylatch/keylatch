//go:build mint_test_endpoint

package version

// variant marks the conformance test build, which takes the GitHub API root
// from the environment and must never be mistaken for a release.
const variant = "testendpoint"
