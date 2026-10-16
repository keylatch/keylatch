//go:build !linux && !darwin && !windows

package contained

// Start always fails: this platform has no sandbox.
func (*Native) Start(Spec) (Child, error) { return nil, ErrUnsupported }

// Probe reports that nothing is available.
func Probe() Report {
	return Report{Backend: "none", Capabilities: []Capability{{Name: "sandbox", Detail: ErrUnsupported.Error()}}}
}
