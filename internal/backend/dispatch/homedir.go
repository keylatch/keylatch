package dispatch

import "os"

func userHomeDirImpl() (string, error) {
	return os.UserHomeDir()
}
