package file

import "github.com/keylatch/keylatch/internal/backend"

// compile-time interface check: FileBackend must satisfy backend.Backend.
// If any method is missing, this line produces a build error immediately.
var _ backend.Backend = (*FileBackend)(nil)
