package llmcontext

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// statFields parses /proc/<pid>/stat: the command name and the fields after
// it. The name is parenthesized and may itself contain spaces or ")".
func statFields(pid int) (comm string, fields []string, err error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", nil, err
	}
	open := bytes.IndexByte(data, '(')
	closing := bytes.LastIndexByte(data, ')')
	if open < 0 || closing < open {
		return "", nil, errors.New("malformed /proc stat")
	}
	fields = strings.Fields(string(data[closing+1:]))
	// fields[0] is the state, fields[1] the parent PID, fields[19] the start time.
	if len(fields) < 20 {
		return "", nil, errors.New("short /proc stat")
	}
	return string(data[open+1 : closing]), fields, nil
}

func readProcessInfo(pid int) (Process, error) {
	comm, fields, err := statFields(pid)
	if err != nil {
		return Process{}, err
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return Process{}, err
	}
	// The executable link and command line of another user's process may be
	// unreadable; the command name alone still identifies the harness.
	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	var argv0 string
	if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		argv0, _, _ = strings.Cut(string(cmdline), "\x00")
	}
	return Process{PID: pid, Start: start, Names: uniqueNames(comm, exe, argv0)}, nil
}

func parentPID(pid int) (int, error) {
	_, fields, err := statFields(pid)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(fields[1])
}
