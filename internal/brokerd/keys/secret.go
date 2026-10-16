package keys

import "fmt"

// secret is key material that sits in locked memory and is zeroed on destroy.
type secret struct {
	b      []byte
	locked bool
}

// lockMem is mlock; tests replace it to simulate a host that refuses.
var lockMem = mlock

func newSecret(b []byte, lock bool) (*secret, error) {
	s := &secret{b: b}
	if err := lockMem(b); err != nil {
		if lock {
			clear(b)
			return nil, fmt.Errorf("keys: lock key memory: %w", err)
		}
		return s, nil
	}
	s.locked = true
	return s, nil
}

func (s *secret) destroy() {
	if s == nil || s.b == nil {
		return
	}
	clear(s.b)
	if s.locked {
		munlock(s.b)
	}
	s.b, s.locked = nil, false
}
