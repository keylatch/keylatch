// Package redactor removes exact secret values, and their common encodings,
// from byte streams and files. Matching is done by a single Aho-Corasick
// automaton so output is released as soon as no pending bytes can still
// become part of a match.
package redactor

import "bytes"

// Marker replaces every redacted span. Its length does not depend on the
// secret.
const Marker = "[REDACTED]"

type edge struct {
	b  byte
	to int32
}

type node struct {
	edges []edge
	fail  int32
	depth int32
	// match is the length of the longest pattern that is a suffix of this
	// node's string, or 0.
	match int32
	// hold is the length of the longest suffix of this node's string that is
	// a prefix of some pattern and can still be extended.
	hold int32
}

// Matcher is an immutable set of secret values and their encodings. It is
// safe for concurrent use; Writers created from it are not.
type Matcher struct {
	nodes []node
}

// NewMatcher builds a Matcher for the given secrets. Values shorter than a
// few bytes are ignored: redacting them would destroy ordinary output while
// hiding nothing useful.
func NewMatcher(secrets ...[]byte) *Matcher {
	m := &Matcher{nodes: []node{{}}}
	for _, secret := range secrets {
		if len(secret) < minSecretLen {
			continue
		}
		for _, v := range variantsOf(secret) {
			m.insert(v.data)
		}
	}
	m.link()
	return m
}

// Empty reports whether the matcher has no patterns.
func (m *Matcher) Empty() bool { return m == nil || len(m.nodes) == 1 }

func (m *Matcher) child(n int32, b byte) int32 {
	for _, e := range m.nodes[n].edges {
		if e.b == b {
			return e.to
		}
	}
	return -1
}

func (m *Matcher) insert(p []byte) {
	var cur int32
	for _, b := range p {
		next := m.child(cur, b)
		if next < 0 {
			next = int32(len(m.nodes)) //nolint:gosec // bounded by the pattern bytes supplied by the caller
			m.nodes = append(m.nodes, node{depth: m.nodes[cur].depth + 1})
			m.nodes[cur].edges = append(m.nodes[cur].edges, edge{b, next})
		}
		cur = next
	}
	m.nodes[cur].match = m.nodes[cur].depth
}

func (m *Matcher) link() {
	queue := make([]int32, 0, len(m.nodes))
	for _, e := range m.nodes[0].edges {
		queue = append(queue, e.to)
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		n := &m.nodes[cur]
		if len(n.edges) > 0 {
			n.hold = n.depth
		} else {
			n.hold = m.nodes[n.fail].hold
		}
		for _, e := range n.edges {
			f := n.fail
			for {
				if t := m.child(f, e.b); t >= 0 {
					m.nodes[e.to].fail = t
					break
				}
				if f == 0 {
					break
				}
				f = m.nodes[f].fail
			}
			if m.nodes[e.to].match == 0 {
				m.nodes[e.to].match = m.nodes[m.nodes[e.to].fail].match
			}
			queue = append(queue, e.to)
		}
	}
}

func (m *Matcher) step(state int32, b byte) int32 {
	for {
		if t := m.child(state, b); t >= 0 {
			return t
		}
		if state == 0 {
			return 0
		}
		state = m.nodes[state].fail
	}
}

// Contains reports whether data holds any secret value or encoding.
func (m *Matcher) Contains(data []byte) bool {
	if m.Empty() {
		return false
	}
	var state int32
	for _, b := range data {
		state = m.step(state, b)
		if m.nodes[state].match > 0 {
			return true
		}
	}
	return false
}

// Redact returns data with every match replaced by Marker.
func (m *Matcher) Redact(data []byte) []byte {
	var out bytes.Buffer
	w := m.NewWriter(&out)
	_, _ = w.Write(data)
	_ = w.Close()
	return out.Bytes()
}
