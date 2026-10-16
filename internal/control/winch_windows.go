package control

import "os"

// resizeSignals never fires: Windows has no terminal resize signal.
func resizeSignals() <-chan os.Signal { return nil }
