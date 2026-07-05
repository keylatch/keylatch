package llmcontext

// session_registry.go
//
// SessionRegistry tracks active LLM-session PIDs and the associated agent
// identifier. It is used by the keylatchd sidecar to answer IPC queries from
// CLI processes that want to know whether they are running inside an LLM session
// (Priority-2 check in IsLLMSession).
//
// Thread-safety: all methods are safe for concurrent use.
//
// This file imports only stdlib packages.

import (
	"sync"
	"time"
)

// sessionEntry records a registered LLM session.
type sessionEntry struct {
	Agent     string
	PID       int
	CreatedAt time.Time
}

// SessionRegistry is a thread-safe set of registered LLM-session PIDs.
type SessionRegistry struct {
	mu      sync.RWMutex
	entries map[int]sessionEntry
}

// NewSessionRegistry creates an empty SessionRegistry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{entries: make(map[int]sessionEntry)}
}

// Register records pid as an active LLM session for agent.
// Calling Register with an already-registered PID overwrites the entry.
func (r *SessionRegistry) Register(pid int, agent string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[pid] = sessionEntry{Agent: agent, PID: pid, CreatedAt: time.Now()}
}

// Deregister removes pid from the registry. No-op if pid is not registered.
func (r *SessionRegistry) Deregister(pid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, pid)
}

// IsActive reports whether pid is currently registered as an LLM session,
// and returns the associated agent name (empty string if not active).
func (r *SessionRegistry) IsActive(pid int) (active bool, agent string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[pid]
	if !ok {
		return false, ""
	}
	return true, e.Agent
}

// Snapshot returns a copy of all current entries as a slice.
// Intended for diagnostics and tests only.
func (r *SessionRegistry) Snapshot() []sessionEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]sessionEntry, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e)
	}
	return out
}
