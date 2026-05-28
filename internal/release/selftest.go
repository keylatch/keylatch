//go:build release

// Package release provides self-test helpers that run only in release builds.
// These checks are compiled in exclusively when the "release" build tag is set,
// ensuring they do not affect normal development or CI test runs.
package release

import (
	"bytes"
	"fmt"

	"github.com/keylatch/keylatch/internal/version"
)

// VerifyNoCanary returns an error if data contains a canary sentinel pattern.
func VerifyNoCanary(data []byte) error {
	if bytes.Contains(data, []byte("KEYLATCH_CANARY_")) {
		return fmt.Errorf("canary sentinel found in release data")
	}
	return nil
}

// VersionIsSet returns an error if the version has not been set via ldflags.
func VersionIsSet() error {
	if version.Version == "dev" {
		return fmt.Errorf("version is not set via ldflags (still 'dev')")
	}
	return nil
}
