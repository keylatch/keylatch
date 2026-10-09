// Package localonly models connection fields whose value is used inside the
// child process and never sent to a host. Such a field is delivered by one of
// three modes instead of a stored raw value.
package localonly

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
)

// Mode is how a local-only field reaches the child, strongest first.
type Mode string

const (
	// Ephemeral generates a random value per session; nothing is stored.
	Ephemeral Mode = "ephemeral"
	// Operation keeps the key in Keylatch and performs operations on request.
	Operation Mode = "operation"
	// Contained delivers the real value only inside a Keylatch sandbox.
	Contained Mode = "contained"
)

// Class is the environment a connection belongs to.
type Class string

const (
	ClassDev  Class = "dev"
	ClassTest Class = "test"
	ClassProd Class = "prod"
)

var (
	// ErrNotAvailable is returned for modes that exist in the model but have
	// no runtime behaviour yet.
	ErrNotAvailable = errors.New("local-only mode not available yet")
	// ErrInvalidMode is returned for an unknown mode name.
	ErrInvalidMode = errors.New("invalid local-only mode")
	// ErrInvalidClass is returned for an unknown connection class.
	ErrInvalidClass = errors.New("invalid connection class")
	// ErrEphemeralClass is returned when ephemeral is requested outside dev/test.
	ErrEphemeralClass = errors.New("ephemeral requires a dev or test connection class")
)

// ParseMode validates a mode name.
func ParseMode(s string) (Mode, error) {
	switch m := Mode(s); m {
	case Ephemeral, Operation, Contained:
		return m, nil
	}
	return "", fmt.Errorf("%w %q (want ephemeral, operation or contained)", ErrInvalidMode, s)
}

// ParseClass validates a class name. The empty string means unclassified.
func ParseClass(s string) (Class, error) {
	switch c := Class(s); c {
	case "", ClassDev, ClassTest, ClassProd:
		return c, nil
	}
	return "", fmt.Errorf("%w %q (want dev, test or prod)", ErrInvalidClass, s)
}

// CheckConnection validates a mode against the connection class. Ephemeral
// values would silently break production behaviour, so only dev and test
// connections may use them.
func CheckConnection(class Class, mode Mode) error {
	if mode == Ephemeral && class != ClassDev && class != ClassTest {
		if class == ClassProd {
			return fmt.Errorf("%w: a prod connection cannot use ephemeral", ErrEphemeralClass)
		}
		return fmt.Errorf("%w: set --class dev or test", ErrEphemeralClass)
	}
	return nil
}

// CheckRun reports whether a mode can be delivered at run time.
func CheckRun(class Class, mode Mode) error {
	if err := CheckConnection(class, mode); err != nil {
		return err
	}
	if mode != Ephemeral {
		return fmt.Errorf("%w: %s", ErrNotAvailable, mode)
	}
	return nil
}

func rank(m Mode) int {
	switch m {
	case Ephemeral:
		return 3
	case Operation:
		return 2
	case Contained:
		return 1
	}
	return 0
}

// Weakens reports whether moving from old to next delivers the secret less
// strongly. Clearing a mode (empty next) is the weakest change.
func Weakens(old, next Mode) bool {
	return rank(next) < rank(old)
}

var suggestSuffixes = []string{"_SECRET", "_SIGNING_KEY", "_ENCRYPTION_KEY"}

// Suggest returns Ephemeral when any of the names looks like a value the
// process only needs to keep consistent within one run and the class is dev
// or test.
func Suggest(class Class, names ...string) (Mode, bool) {
	if class != ClassDev && class != ClassTest {
		return "", false
	}
	for _, n := range names {
		u := strings.ToUpper(n)
		if u == "SECRET_KEY_BASE" {
			return Ephemeral, true
		}
		for _, s := range suggestSuffixes {
			if strings.HasSuffix(u, s) {
				return Ephemeral, true
			}
		}
	}
	return "", false
}

// Shape describes a generated value. With an empty Alphabet the value is
// Length random bytes, base64url-encoded; otherwise it is Length characters
// drawn uniformly from Alphabet.
type Shape struct {
	Length   int
	Alphabet string
}

// DefaultShape is 48 random bytes, base64url-encoded.
var DefaultShape = Shape{Length: 48}

const maxLength = 4096

// Generate returns a cryptographically random value of the given shape.
func Generate(s Shape) (string, error) {
	if s.Length == 0 {
		s.Length = DefaultShape.Length
	}
	if s.Length < 1 || s.Length > maxLength {
		return "", fmt.Errorf("localonly: length %d out of range", s.Length)
	}
	if s.Alphabet == "" {
		b := make([]byte, s.Length)
		if _, err := rand.Read(b); err != nil {
			return "", fmt.Errorf("localonly: random: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
	n := big.NewInt(int64(len(s.Alphabet)))
	out := make([]byte, s.Length)
	for i := range out {
		v, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("localonly: random: %w", err)
		}
		out[i] = s.Alphabet[v.Int64()]
	}
	return string(out), nil
}

// Session hands out one generated value per field for the lifetime of the
// session. Values live only in memory.
type Session struct {
	mu     sync.Mutex
	values map[string]string
}

// NewSession returns an empty session.
func NewSession() *Session {
	return &Session{values: map[string]string{}}
}

// Value returns the session's value for field, generating it on first use.
func (s *Session) Value(field string, shape Shape) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.values[field]; ok {
		return v, nil
	}
	v, err := Generate(shape)
	if err != nil {
		return "", err
	}
	s.values[field] = v
	return v, nil
}
