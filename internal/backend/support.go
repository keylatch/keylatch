package backend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/keylatch/keylatch/internal/manifest"
)

// AllowUnsupportedEnv names the backends the operator opts into although the
// support manifest does not enable them: a comma-separated list of backend names.
const AllowUnsupportedEnv = "KEYLATCH_ALLOW_UNSUPPORTED_BACKEND"

// ErrUnsupportedBackend marks a backend the support manifest does not enable
// and the operator has not opted into.
var ErrUnsupportedBackend = errors.New("backend not supported")

// UnsupportedError is returned by CheckSupported for a backend that is not enabled.
type UnsupportedError struct {
	Name      string
	Status    manifest.Status
	Supported []string
}

func (e *UnsupportedError) Error() string {
	return fmt.Sprintf("backend %q is not supported (%s). Supported managers: %s. "+
		"To keep using it for now, set %s=%s; to move off it, see docs/backends/moving-off-file.md",
		e.Name, e.Status, strings.Join(e.Supported, ", "), AllowUnsupportedEnv, e.Name)
}

func (e *UnsupportedError) Is(target error) bool { return target == ErrUnsupportedBackend }

// SupportedManagers lists the manager backends the manifest enables, in manifest order.
func SupportedManagers() []string {
	var ids []string
	m := manifest.Current()
	for _, e := range m.ByCategory(manifest.CategoryManager) {
		if m.Enabled(e.ID) {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// warnOut receives the opt-in notice; tests replace it.
//
//nolint:gochecknoglobals
var (
	warnOut  io.Writer = os.Stderr
	warnedMu sync.Mutex
	warned   = map[string]bool{}
)

// CheckSupported is the one gate every backend open goes through. name must be
// canonical. A backend the manifest enables passes; any other passes only when
// the process environment's AllowUnsupportedEnv names it, and then the notice
// says what is unproven. It reads the process environment, not an injected
// lookup, so no caller can grant the opt-in on someone else's behalf.
func CheckSupported(name string) error {
	m := manifest.Current()
	if m.Enabled(name) {
		return nil
	}
	entry, tracked := m.Lookup(name)
	status := manifest.Unavailable
	if tracked {
		status = entry.Status
	}
	if optedIn(name, os.Getenv(AllowUnsupportedEnv)) {
		warnUnsupported(name, status, entry.Note)
		return nil
	}
	return &UnsupportedError{Name: name, Status: status, Supported: SupportedManagers()}
}

// OptedIn reports whether the process environment opts into the unsupported
// backend name (canonical).
func OptedIn(name string) bool { return optedIn(name, os.Getenv(AllowUnsupportedEnv)) }

func optedIn(name, list string) bool {
	for _, item := range strings.Split(list, ",") {
		if canonical, ok := CanonicalName(strings.TrimSpace(item)); ok && canonical == name {
			return true
		}
	}
	return false
}

func warnUnsupported(name string, status manifest.Status, note string) {
	warnedMu.Lock()
	defer warnedMu.Unlock()
	if warned[name] {
		return
	}
	warned[name] = true
	if note == "" {
		note = "not tracked by the support manifest"
	}
	fmt.Fprintf(warnOut, "keylatch: using backend %q, which is not supported (%s; opted in with %s). Unproven: %s. Supported managers: %s\n",
		name, status, AllowUnsupportedEnv, note, strings.Join(SupportedManagers(), ", "))
}
