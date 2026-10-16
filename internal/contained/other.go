//go:build !linux

package contained

// Native is unavailable off Linux: the macOS and Windows runtimes are separate
// work and until they land those platforms refuse the contained tier.
type Native struct {
	Binary  string
	Cgroups bool
}

// Start always fails.
func (*Native) Start(Spec) (Child, error) { return nil, ErrUnsupported }

// MaybeRun never runs a helper.
func MaybeRun() bool { return false }

// Probe reports that nothing is available.
func Probe() Report {
	return Report{Backend: "none", Capabilities: []Capability{{Name: "sandbox", Detail: ErrUnsupported.Error()}}}
}
