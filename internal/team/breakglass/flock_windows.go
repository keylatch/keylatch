//go:build windows

package breakglass

import "os"

// flockAcquire is a no-op on Windows. Windows uses mandatory file locking via
// LockFileEx; advisory flock-style locking is not available. Break-glass
// operations on Windows rely on the OS-level file-creation atomicity of
// os.OpenFile with O_CREATE|O_EXCL for serialisation at the counter level.
func flockAcquire(_ *os.File) error { return nil }

// flockRelease is a no-op on Windows.
func flockRelease(_ *os.File) {}
