package contained

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const cgroupRoot = "/sys/fs/cgroup"

// cgroup is a leaf cgroup v2 directory for one run: a place to put every
// process of the sandbox so they can be killed together and bounded.
type cgroup struct {
	dir  string
	file *os.File
	// Notes lists limits that could not be applied, for the audit trail.
	Notes []string
}

// ownCgroup returns the cgroup directory the process runs in, read from
// selfCgroup (/proc/self/cgroup) below root.
func ownCgroup(selfCgroup, root string) (string, error) {
	b, err := os.ReadFile(selfCgroup)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			return filepath.Join(root, filepath.Clean("/"+rest)), nil
		}
	}
	return "", errors.New("contained: this host does not use cgroup v2")
}

// newCgroup creates a leaf below parent and applies the limits it can.
func newCgroup(parent string, lim Limits) (*cgroup, error) {
	var id [6]byte
	_, _ = rand.Read(id[:])
	dir := filepath.Join(parent, "keylatch-run-"+hex.EncodeToString(id[:]))
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("contained: create cgroup: %w", err)
	}
	c := &cgroup{dir: dir}
	set := func(file, value, what string) {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(value), 0o600); err != nil {
			c.Notes = append(c.Notes, what+" limit not applied: "+err.Error())
		}
	}
	if lim.MemoryBytes > 0 {
		set("memory.max", strconv.FormatInt(lim.MemoryBytes, 10), "memory")
	}
	if lim.PIDs > 0 {
		set("pids.max", strconv.Itoa(lim.PIDs), "pids")
	}
	if lim.CPUPercent > 0 {
		set("cpu.max", fmt.Sprintf("%d 100000", lim.CPUPercent*1000), "cpu")
	}
	f, err := os.Open(dir)
	if err != nil {
		_ = os.Remove(dir)
		return nil, err
	}
	c.file = f
	return c, nil
}

// FD is the directory descriptor clone places the child in.
func (c *cgroup) FD() int { return int(c.file.Fd()) } //nolint:gosec // G115: a descriptor fits in int

// Kill ends every process in the cgroup.
func (c *cgroup) Kill() {
	if err := os.WriteFile(filepath.Join(c.dir, "cgroup.kill"), []byte("1"), 0o600); err == nil {
		return
	}
	b, _ := os.ReadFile(filepath.Join(c.dir, "cgroup.procs"))
	for _, f := range strings.Fields(string(b)) {
		if pid, err := strconv.Atoi(f); err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

// Remove deletes the leaf once its processes are gone.
func (c *cgroup) Remove() {
	_ = c.file.Close()
	_ = os.Remove(c.dir)
}
