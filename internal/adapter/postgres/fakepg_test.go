package postgres

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakePG is an in-process PostgreSQL wire server. It speaks enough of the
// protocol to authenticate a client by cleartext, MD5 or SCRAM-SHA-256, answer
// a simple query with the role it authenticated, and record what it was sent.
type fakePG struct {
	ln       net.Listener
	mode     string
	user     string
	password string
	tls      *tls.Config

	mu       sync.Mutex
	startups []map[string]string
	cancels  [][]byte
	conns    int
}

const (
	modeScram     = "scram"
	modeMD5       = "md5"
	modeCleartext = "cleartext"
)

func startFakePG(t *testing.T, mode, user, password string, tlsCfg *tls.Config) *fakePG {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakePG{ln: ln, mode: mode, user: user, password: password, tls: tlsCfg}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakePG) addr() string { return f.ln.Addr().String() }

func (f *fakePG) seenStartups() []map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.startups...)
}

func (f *fakePG) seenCancels() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.cancels...)
}

func (f *fakePG) connections() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns
}

func (f *fakePG) fail(c net.Conn, code, msg string) {
	_ = writeMessage(c, 'E', errorBody(code, msg))
}

func (f *fakePG) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	conn := c
	for {
		code, body, err := readStartup(conn)
		if err != nil {
			return
		}
		switch code {
		case codeSSLRequest:
			if f.tls == nil {
				_, _ = conn.Write([]byte{'N'})
				continue
			}
			_, _ = conn.Write([]byte{'S'})
			conn = tls.Server(conn, f.tls)
			continue
		case codeCancel:
			f.mu.Lock()
			f.cancels = append(f.cancels, body)
			f.mu.Unlock()
			return
		}
		st, err := parseStartup(body)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.startups = append(f.startups, st.params)
		f.mu.Unlock()
		if st.get("user") != f.user {
			f.fail(conn, "28000", "role does not exist")
			return
		}
		if !f.authenticate(conn) {
			return
		}
		_ = writeMessage(conn, 'R', authRequest(authOK))
		_ = writeMessage(conn, 'S', []byte("server_version\x0016.0\x00"))
		key := make([]byte, 8)
		binary.BigEndian.PutUint32(key, 4242)
		binary.BigEndian.PutUint32(key[4:], 777)
		_ = writeMessage(conn, 'K', key)
		_ = writeMessage(conn, 'Z', []byte{'I'})
		f.queries(conn, st.get("database"))
		return
	}
}

func (f *fakePG) queries(conn net.Conn, database string) {
	for {
		m, err := readMessage(conn)
		if err != nil || m.typ == 'X' {
			return
		}
		if m.typ != 'Q' {
			continue
		}
		row := f.user + "@" + database
		var rd bytes.Buffer
		_ = binary.Write(&rd, binary.BigEndian, uint16(1))
		rd.WriteString("who\x00")
		rd.Write(make([]byte, 6))
		_ = binary.Write(&rd, binary.BigEndian, uint32(25))
		rd.Write(make([]byte, 8))
		_ = writeMessage(conn, 'T', rd.Bytes())
		var dr bytes.Buffer
		_ = binary.Write(&dr, binary.BigEndian, uint16(1))
		_ = binary.Write(&dr, binary.BigEndian, uint32(len(row)))
		dr.WriteString(row)
		_ = writeMessage(conn, 'D', dr.Bytes())
		_ = writeMessage(conn, 'C', []byte("SELECT 1\x00"))
		_ = writeMessage(conn, 'Z', []byte{'I'})
	}
}

func (f *fakePG) authenticate(conn net.Conn) bool {
	switch f.mode {
	case modeCleartext:
		_ = writeMessage(conn, 'R', authRequest(authCleartext))
		m, err := readMessage(conn)
		pw, _, _ := cstring(m.body)
		if err != nil || pw != f.password {
			f.fail(conn, "28P01", "password authentication failed")
			return false
		}
	case modeMD5:
		salt := []byte{1, 2, 3, 4}
		_ = writeMessage(conn, 'R', authRequest(authMD5, salt...))
		// The adapter refuses MD5, so any answer is a failure.
		_, _ = readMessage(conn)
		f.fail(conn, "28P01", "password authentication failed")
		return false
	case modeScram:
		return f.scram(conn)
	}
	return true
}

func (f *fakePG) scram(conn net.Conn) bool {
	_ = writeMessage(conn, 'R', authRequest(authSASL, append([]byte(scramMechanism), 0, 0)...))
	m, err := readMessage(conn)
	if err != nil || m.typ != 'p' {
		return false
	}
	mech, rest, _ := cstring(m.body)
	if mech != scramMechanism || len(rest) < 4 {
		return false
	}
	first := string(rest[4:])
	bare := strings.TrimPrefix(first, "n,,")
	cnonce := parseAttrs(bare)["r"]

	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	const iter = 4096
	nonce := cnonce + "srv" + strconv.Itoa(iter)
	serverFirst := "r=" + nonce + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=" + strconv.Itoa(iter)
	_ = writeMessage(conn, 'R', authRequest(authSASLContinu, []byte(serverFirst)...))

	m, err = readMessage(conn)
	if err != nil || m.typ != 'p' {
		return false
	}
	final := string(m.body)
	attrs := parseAttrs(final)
	withoutProof := final[:strings.LastIndex(final, ",p=")]
	salted, _ := pbkdf2.Key(sha256.New, f.password, salt, iter, sha256.Size)
	clientKey := hmacSum(salted, "Client Key")
	stored := sha256.Sum256(clientKey)
	authMessage := bare + "," + serverFirst + "," + withoutProof
	sig := hmacSum(stored[:], authMessage)
	proof, _ := base64.StdEncoding.DecodeString(attrs["p"])
	ok := len(proof) == len(sig) && attrs["r"] == nonce
	for i := 0; ok && i < len(sig); i++ {
		ok = proof[i]^sig[i] == clientKey[i]
	}
	if !ok {
		f.fail(conn, "28P01", "password authentication failed")
		return false
	}
	serverSig := hmacSum(hmacSum(salted, "Server Key"), authMessage)
	_ = writeMessage(conn, 'R', authRequest(authSASLFinal, []byte("v="+base64.StdEncoding.EncodeToString(serverSig))...))
	return true
}

func hmacSum(key []byte, msg string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// client is a minimal frontend: it connects, answers the cleartext password
// request with the token and runs simple queries.
type client struct {
	conn net.Conn
	// authError is the ErrorResponse that ended the handshake, if any.
	authError *serverError
	// raw is everything the server sent, for secret scans.
	raw bytes.Buffer
	key [2]uint32
}

func (c *client) read() (message, error) {
	var head [5]byte
	if _, err := io.ReadFull(c.conn, head[:]); err != nil {
		return message{}, err
	}
	c.raw.Write(head[:])
	n := binary.BigEndian.Uint32(head[1:])
	body := make([]byte, n-4)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return message{}, err
	}
	c.raw.Write(body)
	return message{typ: head[0], body: body}, nil
}

func dialClient(t *testing.T, addr, user, database, token string, extra ...string) *client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	c := &client{conn: conn}

	// A client that asks for TLS first is told no and carries on in clear.
	var ssl [8]byte
	binary.BigEndian.PutUint32(ssl[:4], 8)
	binary.BigEndian.PutUint32(ssl[4:], codeSSLRequest)
	_, err = conn.Write(ssl[:])
	require.NoError(t, err)
	var answer [1]byte
	_, err = io.ReadFull(conn, answer[:])
	require.NoError(t, err)
	require.Equal(t, byte('N'), answer[0])

	order := []string{"user", "database"}
	params := map[string]string{"user": user, "database": database}
	for i := 0; i+1 < len(extra); i += 2 {
		order = append(order, extra[i])
		params[extra[i]] = extra[i+1]
	}
	_, err = conn.Write(encodeStartup(order, params))
	require.NoError(t, err)

	for {
		m, err := c.read()
		if err != nil {
			return c
		}
		switch m.typ {
		case 'R':
			switch binary.BigEndian.Uint32(m.body) {
			case authCleartext:
				require.NoError(t, writeMessage(conn, 'p', append([]byte(token), 0)))
			case authOK:
			}
		case 'K':
			c.key = [2]uint32{binary.BigEndian.Uint32(m.body), binary.BigEndian.Uint32(m.body[4:])}
		case 'E':
			c.authError = parseError(m.body)
			return c
		case 'Z':
			return c
		}
	}
}

// query runs a simple query and returns the first column of the first row.
func (c *client) query(t *testing.T, sql string) string {
	t.Helper()
	require.NoError(t, writeMessage(c.conn, 'Q', append([]byte(sql), 0)))
	out := ""
	for {
		m, err := c.read()
		require.NoError(t, err)
		switch m.typ {
		case 'D':
			n := binary.BigEndian.Uint32(m.body[2:])
			out = string(m.body[6 : 6+n])
		case 'Z':
			return out
		}
	}
}
