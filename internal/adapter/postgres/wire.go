// Package postgres is the protocol adapter for PostgreSQL. It terminates the
// client's authentication with a per-session token, authenticates upstream
// with the stored credential, and relays the rest of the stream untouched.
// The child holds the token only; the database password never leaves the
// adapter's process.
package postgres

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Protocol constants from the PostgreSQL frontend/backend protocol.
const (
	protocolV3      = 196608
	codeCancel      = 80877102
	codeSSLRequest  = 80877103
	codeGSSRequest  = 80877104
	maxStartupLen   = 10 << 10
	maxMessageLen   = 1 << 20
	authOK          = 0
	authCleartext   = 3
	authMD5         = 5
	authSASL        = 10
	authSASLContinu = 11
	authSASLFinal   = 12
)

var (
	errStartup  = errors.New("postgres: malformed startup message")
	errProtocol = errors.New("postgres: unexpected message")
)

// startup is a decoded StartupMessage.
type startup struct {
	params map[string]string
	order  []string
}

func (s startup) get(k string) string { return s.params[k] }

// readStartup reads the first packet of a connection: a startup message, an
// SSL or GSS request, or a cancel request. For the latter it returns the code
// and the body, so the caller can answer or forward it.
func readStartup(r io.Reader) (code uint32, body []byte, err error) {
	var head [8]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(head[:4])
	code = binary.BigEndian.Uint32(head[4:])
	if n < 8 || n > maxStartupLen {
		return 0, nil, errStartup
	}
	body = make([]byte, n-8)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return code, body, nil
}

func parseStartup(body []byte) (startup, error) {
	s := startup{params: map[string]string{}}
	parts := bytes.Split(body, []byte{0})
	if len(parts) < 2 || len(parts[len(parts)-1]) != 0 || len(parts[len(parts)-2]) != 0 {
		return s, errStartup
	}
	parts = parts[:len(parts)-2]
	if len(parts)%2 != 0 {
		return s, errStartup
	}
	for i := 0; i < len(parts); i += 2 {
		k, v := string(parts[i]), string(parts[i+1])
		if k == "" {
			return s, errStartup
		}
		if _, dup := s.params[k]; !dup {
			s.order = append(s.order, k)
		}
		s.params[k] = v
	}
	return s, nil
}

// encodeStartup builds a protocol 3.0 StartupMessage from params, in order.
func encodeStartup(order []string, params map[string]string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 0, 0})
	_ = binary.Write(&b, binary.BigEndian, uint32(protocolV3))
	for _, k := range order {
		b.WriteString(k)
		b.WriteByte(0)
		b.WriteString(params[k])
		b.WriteByte(0)
	}
	b.WriteByte(0)
	out := b.Bytes()
	binary.BigEndian.PutUint32(out[:4], uint32(len(out))) //nolint:gosec // G115: a handful of startup parameters
	return out
}

// message is one typed backend or frontend message.
type message struct {
	typ  byte
	body []byte
}

func readMessage(r io.Reader) (message, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return message{}, err
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n < 4 || n > maxMessageLen {
		return message{}, errProtocol
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return message{}, err
	}
	return message{typ: head[0], body: body}, nil
}

func writeMessage(w io.Writer, typ byte, body []byte) error {
	buf := make([]byte, 5+len(body))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:], uint32(len(body)+4)) //nolint:gosec // G115: bodies are protocol messages bounded by maxMessageLen
	copy(buf[5:], body)
	_, err := w.Write(buf)
	return err
}

func authRequest(code uint32, extra ...byte) []byte {
	b := make([]byte, 4, 4+len(extra))
	binary.BigEndian.PutUint32(b, code)
	return append(b, extra...)
}

// errorBody encodes an ErrorResponse with the fields a client prints.
func errorBody(sqlstate, msg string) []byte {
	var b bytes.Buffer
	for _, f := range [][2]string{{"S", "FATAL"}, {"V", "FATAL"}, {"C", sqlstate}, {"M", msg}} {
		b.WriteString(f[0])
		b.WriteString(f[1])
		b.WriteByte(0)
	}
	b.WriteByte(0)
	return b.Bytes()
}

// serverError is an ErrorResponse received from the database.
type serverError struct{ code, msg string }

func (e *serverError) Error() string {
	return fmt.Sprintf("postgres: server error %s: %s", e.code, e.msg)
}

func parseError(body []byte) *serverError {
	e := &serverError{}
	for _, f := range bytes.Split(body, []byte{0}) {
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case 'C':
			e.code = string(f[1:])
		case 'M':
			e.msg = string(f[1:])
		}
	}
	return e
}

// cstring reads a NUL-terminated string from the front of b.
func cstring(b []byte) (string, []byte, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

func hasMechanism(list []byte, want string) bool {
	for len(list) > 0 && list[0] != 0 {
		m, rest, ok := cstring(list)
		if !ok {
			return false
		}
		if strings.EqualFold(m, want) {
			return true
		}
		list = rest
	}
	return false
}
