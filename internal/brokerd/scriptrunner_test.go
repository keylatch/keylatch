package brokerd

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// scriptRunner answers host commands from a table keyed by the command line
// prefix, and records every call.
type scriptRunner struct {
	mu    sync.Mutex
	calls []string
	stdin map[string][]byte
	out   map[string]string
	fail  map[string]error
}

func (r *scriptRunner) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, line)
	if stdin != nil {
		if r.stdin == nil {
			r.stdin = map[string][]byte{}
		}
		r.stdin[line] = append([]byte(nil), stdin...)
	}
	for prefix, err := range r.fail {
		if strings.HasPrefix(line, prefix) {
			return []byte(r.out[prefix]), err
		}
	}
	for prefix, out := range r.out {
		if strings.HasPrefix(line, prefix) {
			return []byte(out), nil
		}
	}
	return nil, nil
}

func (r *scriptRunner) called(prefix string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (r *scriptRunner) count(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

var errScript = errors.New("scripted failure")
