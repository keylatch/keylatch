package brokerd

import (
	"os"
	"path/filepath"
)

// DefaultStateRoot is where the service keeps its state, under %ProgramData%
// with a DACL that names only the service SID and SYSTEM.
var DefaultStateRoot = filepath.Join(programData(), "keylatch")

// DefaultSocket is the named pipe the clients connect to.
const DefaultSocket = `\\.\pipe\keylatch-broker`

const presenceHint = "install the presence helper with 'keylatch broker enroll-presence'"

func programData() string {
	if d := os.Getenv("ProgramData"); d != "" {
		return d
	}
	return `C:\ProgramData`
}
