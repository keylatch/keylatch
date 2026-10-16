package doctor

import (
	"context"
	"fmt"
	"os"
)

const relayBinary = "keylatch-relay"

// checkRelay looks at the optional fallback binary for harnesses whose
// sandbox cannot reach a Unix socket. It is run outside the sandbox as an
// excluded command, so a copy the user can overwrite would let anything that
// runs as the user replace it.
func checkRelay(lookPath func(string) (string, error)) Check {
	return func(_ context.Context) Status {
		st := Status{Name: "daemon.relay", Section: "daemon", Tags: []string{"relay"}}
		path, err := lookPath(relayBinary)
		if err != nil {
			st.OK = true
			st.Detail = relayBinary + " is not installed (only needed where the harness sandbox cannot reach a Unix socket)"
			return st
		}
		info, err := os.Stat(path)
		if err != nil {
			st.Warn, st.OK = true, true
			st.Detail = fmt.Sprintf("%s could not be inspected: %v", path, err)
			return st
		}
		if ownedByUser(info) && info.Mode().Perm()&0o200 != 0 {
			st.Warn, st.OK = true, true
			st.Detail = fmt.Sprintf("%s is writable by your user, so a process running as you can replace a command your harness runs outside its sandbox", path)
			st.Fix = fmt.Sprintf("Install it root- or package-owned: sudo install -o root -m 0755 %s /usr/local/bin/%s, then list that path as the harness's excluded command.", path, relayBinary)
			return st
		}
		st.OK, st.Detail = true, path+" is not writable by your user"
		return st
	}
}
