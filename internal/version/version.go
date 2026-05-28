// Package version exposes build-time version metadata injected via ldflags.
// Default values ("1.0.0-dev", "unknown") are safe for local builds and tests.
package version

import "fmt"

// Version, Commit, and BuildDate are set by the release build via ldflags:
//
//	-X 'github.com/keylatch/keylatch/internal/version.Version={{.Version}}'
//	-X 'github.com/keylatch/keylatch/internal/version.Commit={{.Commit}}'
//	-X 'github.com/keylatch/keylatch/internal/version.BuildDate={{.Date}}'
var (
	Version   = "1.0.0-dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

// String returns the canonical human-readable version string.
func String() string {
	return fmt.Sprintf("keylatch %s (%s) built %s", Version, Commit, BuildDate)
}

// versionJSON is the JSON-serialisable shape of the version metadata.
type versionJSON struct {
	Version   string `json:"Version"`
	Commit    string `json:"Commit"`
	BuildDate string `json:"BuildDate"`
}

// JSON returns a value suitable for JSON marshalling via encoding/json.
func JSON() any {
	return versionJSON{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
	}
}
