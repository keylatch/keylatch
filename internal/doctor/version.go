package doctor

import "runtime/debug"

// version returns the current binary version from build info.
// Falls back to "dev" if not available (e.g. running via go run or go test).
func version() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}
