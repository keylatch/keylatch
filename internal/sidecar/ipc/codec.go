// Package ipc implements the HMAC-authenticated, CBOR-framed IPC protocol
// between the Tauri desktop shell (Rust) and the keylatchd sidecar (Go).
//
// Frame format (over Unix domain socket):
//
//	[ 4-byte big-endian length | CBOR body | 32-byte HMAC-SHA256 tag ]
//
// The HMAC is computed over length_bytes || body_bytes.
// A frame whose HMAC tag does not verify is rejected with ErrHMACMismatch;
// the connection is closed and no error detail is surfaced to the caller
// (S14-8 — no HMAC oracle).
package ipc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"
)

const (
	// hmacTagSize is the size of the HMAC-SHA256 authentication tag in bytes.
	hmacTagSize = 32
	// maxFrameSize is the maximum allowed body size (1 MiB) to prevent
	// memory-exhaustion attacks from a malicious IPC peer.
	maxFrameSize = 1 << 20 // 1 MiB
)

// ErrHMACMismatch is returned (and logged) when a received frame fails
// HMAC-SHA256 verification. The connection is closed without surfacing
// detail to the peer (S14-8).
var ErrHMACMismatch = errors.New("ipc: HMAC mismatch — frame rejected")

// ErrFrameTooLarge is returned when a peer sends a frame whose declared
// length exceeds maxFrameSize.
var ErrFrameTooLarge = errors.New("ipc: frame too large")

// FrameWriter writes HMAC-authenticated, length-prefixed CBOR frames to w.
type FrameWriter struct {
	w   io.Writer
	key []byte
}

// NewFrameWriter creates a FrameWriter that authenticates frames with key.
// key must be exactly 32 bytes (the shared HMAC-SHA256 secret).
func NewFrameWriter(w io.Writer, key []byte) *FrameWriter {
	k := make([]byte, len(key))
	copy(k, key)
	return &FrameWriter{w: w, key: k}
}

// Write serialises v as CBOR, prepends a 4-byte big-endian length, and
// appends a 32-byte HMAC-SHA256 tag computed over length||body.
func (fw *FrameWriter) Write(v any) error {
	body, err := cbor.Marshal(v)
	if err != nil {
		return err
	}

	// Build the 4-byte length header.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(body))) //nolint:gosec // G115: body length is bounded by maxFrameSize (1 MiB), well within uint32 range

	// Compute HMAC over length||body.
	mac := hmac.New(sha256.New, fw.key)
	mac.Write(lenBuf[:])
	mac.Write(body)
	tag := mac.Sum(nil)

	// Write length + body + tag in a single call to avoid short writes.
	frame := make([]byte, 0, 4+len(body)+hmacTagSize)
	frame = append(frame, lenBuf[:]...)
	frame = append(frame, body...)
	frame = append(frame, tag...)

	_, err = fw.w.Write(frame)
	return err
}

// FrameReader reads HMAC-authenticated, length-prefixed CBOR frames from r.
type FrameReader struct {
	r   io.Reader
	key []byte
}

// NewFrameReader creates a FrameReader that verifies frames with key.
func NewFrameReader(r io.Reader, key []byte) *FrameReader {
	k := make([]byte, len(key))
	copy(k, key)
	return &FrameReader{r: r, key: k}
}

// Read reads the next frame from the underlying reader, verifies its HMAC,
// and decodes the CBOR body into v.
// Returns ErrHMACMismatch if the tag does not verify (caller must close conn).
// Returns ErrFrameTooLarge if the declared body length exceeds maxFrameSize.
func (fr *FrameReader) Read(v any) error {
	// Read 4-byte length header.
	var lenBuf [4]byte
	if _, err := io.ReadFull(fr.r, lenBuf[:]); err != nil {
		return err
	}
	bodyLen := binary.BigEndian.Uint32(lenBuf[:])
	if bodyLen > maxFrameSize {
		return ErrFrameTooLarge
	}

	// Read body.
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(fr.r, body); err != nil {
		return err
	}

	// Read HMAC tag.
	tag := make([]byte, hmacTagSize)
	if _, err := io.ReadFull(fr.r, tag); err != nil {
		return err
	}

	// Verify HMAC over length||body (constant-time comparison).
	mac := hmac.New(sha256.New, fr.key)
	mac.Write(lenBuf[:])
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return ErrHMACMismatch
	}

	// Decode CBOR body.
	return cbor.Unmarshal(body, v)
}
