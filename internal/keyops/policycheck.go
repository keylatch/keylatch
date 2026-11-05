package keyops

// WithPolicyCheck returns a session service that rechecks external authorization
// whenever a protocol operation discovers or authorizes a key.
func (s *Service) WithPolicyCheck(check func() error) *Service {
	return &Service{policy: checkedPolicy{source: s.policy, check: check}, keys: s.keys, audit: s.audit}
}

type checkedPolicy struct {
	source PolicySource
	check  func() error
}

func (p checkedPolicy) Lookup(connection, field string) (KeyRef, error) {
	if err := p.check(); err != nil {
		return KeyRef{}, err
	}
	return p.source.Lookup(connection, field)
}

func (p checkedPolicy) SSHKeys() ([]KeyRef, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return p.source.SSHKeys()
}

func (p checkedPolicy) GPGKeys() ([]KeyRef, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	return p.source.GPGKeys()
}
