package mysql

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

const (
	longPassword     uint32 = 1
	longFlag         uint32 = 4
	connectDB        uint32 = 8
	protocol41       uint32 = 512
	ssl              uint32 = 2048
	transactions     uint32 = 8192
	secureConnection uint32 = 32768
	multiResults     uint32 = 1 << 17
	pluginAuth       uint32 = 1 << 19
	capabilities            = longPassword | longFlag | connectDB | protocol41 | transactions | secureConnection | multiResults | pluginAuth
	plugin                  = "caching_sha2_password"
)

func readPacket(r io.Reader, seq byte) ([]byte, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, err
	}
	n := int(head[0]) | int(head[1])<<8 | int(head[2])<<16
	if head[3] != seq || n == 0 || n > 1<<20 {
		return nil, errors.New("mysql: invalid packet")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return body, err
}

func writePacket(w io.Writer, seq byte, body []byte) error {
	if len(body) > 1<<20 {
		return errors.New("mysql: packet exceeds limit")
	}
	n := len(body)
	head := []byte{byte(n & 255), byte((n >> 8) & 255), byte((n >> 16) & 255), seq}
	if _, err := w.Write(head); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func greeting(nonce []byte) []byte {
	b := append([]byte{10}, []byte("8.0.0-Keylatch\x00")...)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = append(b, nonce[:8]...)
	b = append(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(capabilities&65535))
	b = append(b, 45, 2, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(capabilities>>16))
	b = append(b, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, nonce[8:]...)
	b = append(b, 0)
	b = append(b, plugin...)
	return append(b, 0)
}

func scramble(password, nonce []byte) []byte {
	a := sha256.Sum256(password)
	b := sha256.Sum256(a[:])
	h := sha256.New()
	_, _ = h.Write(b[:])
	_, _ = h.Write(nonce)
	out := h.Sum(nil)
	for i := range out {
		out[i] ^= a[i]
	}
	clear(a[:])
	clear(b[:])
	return out
}

func takeString(b []byte) (string, []byte, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return "", nil, errors.New("mysql: unterminated string")
	}
	return string(b[:i]), b[i+1:], nil
}

func parseGreeting(b []byte) (uint32, []byte, error) {
	bad := errors.New("mysql: unsupported greeting")
	if len(b) < 1 || b[0] != 10 {
		return 0, nil, bad
	}
	_, b, err := takeString(b[1:])
	if err != nil || len(b) < 31 {
		return 0, nil, bad
	}
	nonce := append([]byte(nil), b[4:12]...)
	caps := uint32(binary.LittleEndian.Uint16(b[13:15])) | uint32(binary.LittleEndian.Uint16(b[18:20]))<<16
	if caps&pluginAuth == 0 || b[20] != 21 || len(b) < 44 {
		return 0, nil, bad
	}
	nonce = append(nonce, b[31:43]...)
	name, _, err := takeString(b[44:])
	if err != nil || name != plugin {
		return 0, nil, bad
	}
	return caps, nonce, nil
}

type login struct {
	caps     uint32
	charset  byte
	database string
	auth     []byte
}

func parseLogin(b []byte) (login, error) {
	bad := errors.New("mysql: unsupported client login")
	if len(b) < 33 {
		return login{}, bad
	}
	l := login{caps: binary.LittleEndian.Uint32(b[:4]), charset: b[8]}
	// TLS and compression cannot be enabled on the loopback protocol stream.
	const forbidden = uint32(32 | 2048)
	if l.caps&(protocol41|secureConnection|pluginAuth) != (protocol41|secureConnection|pluginAuth) || l.caps&forbidden != 0 {
		return login{}, bad
	}
	_, b, err := takeString(b[32:])
	if err != nil || len(b) == 0 {
		return login{}, bad
	}
	n := int(b[0])
	b = b[1:]
	if n >= 251 || len(b) < n {
		return login{}, bad
	}
	l.auth = append([]byte(nil), b[:n]...)
	b = b[n:]
	if l.caps&connectDB != 0 {
		l.database, b, err = takeString(b)
		if err != nil {
			return login{}, bad
		}
	}
	name, _, err := takeString(b)
	if err != nil || name != plugin {
		return login{}, bad
	}
	return l, nil
}

func loginPacket(caps uint32, charset byte, user, database string, auth []byte) []byte {
	authLen := len(auth)
	if authLen > 250 {
		return nil
	}
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, caps)
	binary.LittleEndian.PutUint32(b[4:], 1<<20)
	b[8] = charset
	b = append(b, user...)
	b = append(b, 0, byte(authLen))
	b = append(b, auth...)
	if caps&connectDB != 0 {
		b = append(b, database...)
		b = append(b, 0)
	}
	b = append(b, plugin...)
	return append(b, 0)
}

func refuse(w io.Writer, seq byte) {
	_ = writePacket(w, seq, append([]byte{255, 21, 4, '#'}, []byte("28000Keylatch authentication failed")...))
}
