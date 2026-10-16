package hook

// IsEnvFileName reports whether the guard denies agent reads of a file with
// this base name because it is an env file that holds secrets.
func IsEnvFileName(name string) bool { return isEnvFileName(name) }
