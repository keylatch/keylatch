//go:build !linux

package contained

// Native starts children under the platform's own sandbox: Seatbelt on macOS,
// an AppContainer and a job object on Windows. Neither re-executes the binary,
// so Binary and Cgroups are kept only so callers build one value on every OS.
type Native struct {
	Binary  string
	Cgroups bool
}

// MaybeRun never runs a helper: nothing re-executes the binary off Linux.
func MaybeRun() bool { return false }
