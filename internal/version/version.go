// Package version exposes build-time version metadata injected via ldflags,
// falling back to the Go build info for binaries built without them (for
// example `go install ...@<commit>`). The remaining defaults ("0.0.0-devbuild",
// "unknown") are safe for local builds and tests. They are deliberately below
// the v0.9.x release train (never "1.0.0-dev") so an un-ldflagged local build
// can never be mistaken for a version ahead of an actual release.
package version

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
)

const (
	defaultVersion = "0.0.0-devbuild"
	unknown        = "unknown"
)

// Version, Commit, and BuildDate are set by the release build via ldflags:
//
//	-X 'github.com/keylatch/keylatch/internal/version.Version={{.Version}}'
//	-X 'github.com/keylatch/keylatch/internal/version.Commit={{.Commit}}'
//	-X 'github.com/keylatch/keylatch/internal/version.BuildDate={{.Date}}'
var (
	Version   = defaultVersion
	Commit    = unknown
	BuildDate = unknown
)

func init() {
	if bi, ok := debug.ReadBuildInfo(); ok {
		Version, Commit, BuildDate = fromBuildInfo(bi, Version, Commit, BuildDate)
	}
}

// pseudoRevision matches the trailing 12-character revision of a Go module
// pseudo-version such as v0.9.10-0.20261016101500-0123456789ab.
var pseudoRevision = regexp.MustCompile(`-([0-9a-f]{12})(?:\+dirty)?$`)

// fromBuildInfo fills values that ldflags left at their defaults from the
// module version and VCS stamps the Go toolchain embeds. Values set by
// ldflags always win.
func fromBuildInfo(bi *debug.BuildInfo, ver, commit, date string) (string, string, string) {
	mainVersion := bi.Main.Version
	if ver == defaultVersion && mainVersion != "" && mainVersion != "(devel)" {
		ver = strings.TrimPrefix(mainVersion, "v")
	}

	var revision, vcsTime string
	var modified bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.time":
			vcsTime = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if revision == "" {
		if m := pseudoRevision.FindStringSubmatch(mainVersion); m != nil {
			revision = m[1]
		}
	}
	if commit == unknown && revision != "" {
		commit = revision
		if modified {
			commit += "-dirty"
		}
	}
	if date == unknown && vcsTime != "" {
		date = vcsTime
	}
	return ver, commit, date
}

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
