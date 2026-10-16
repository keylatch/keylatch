//go:build !windows

package llmcontext

// chainFrom returns pid followed by its ancestors, up to the first one that
// cannot be read.
func chainFrom(pid int) []Process {
	var chain []Process
	for i := 0; i < maxAncestry && pid > 0; i++ {
		p, err := readProcessInfo(pid)
		if err != nil {
			break
		}
		chain = append(chain, p)
		ppid, err := parentPID(pid)
		if err != nil || ppid == pid || ppid <= 0 {
			break
		}
		pid = ppid
	}
	return chain
}
