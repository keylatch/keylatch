// Package auditverify provides a standalone HMAC-chain verification helper
// for keylatch audit logs. It operates on raw log bytes rather than file paths,
// making it suitable for in-memory test assertions and streaming verification.
package auditverify

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/keylatch/keylatch/internal/audit"
	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
)

// Sentinel errors for each chain-tampering scenario.
var (
	// ErrChainDeleted is returned when entries appear to have been removed
	// from the log (sequence number jumps forward by more than 1).
	ErrChainDeleted = errors.New("audit: chain entry deleted")

	// ErrChainTruncated is returned when the log appears to have been cut
	// short (a malformed or incomplete final line with no valid header).
	ErrChainTruncated = errors.New("audit: chain truncated")

	// ErrChainReordered is returned when a sequence number decreases or
	// repeats relative to the previous entry.
	ErrChainReordered = errors.New("audit: chain reordered")

	// ErrChainCorrupted is returned when an HMAC chain link does not match
	// (the current line's prev_hmac does not equal the HMAC computed for the
	// previous line).
	ErrChainCorrupted = errors.New("audit: chain corrupted")
)

// chainHeader mirrors the unexported type in internal/audit.
type chainHeader struct {
	Seq      int64  `json:"seq"`
	PrevHMAC string `json:"prev_hmac"`
	TSUnix   int64  `json:"ts_unix"`
}

// Verify returns nil if the HMAC chain in logBytes is intact.
// Returns one of the four sentinel errors on any tampering detection.
//
// salt is the 32-byte HMAC salt (same one used with audit.Open).
func Verify(logBytes []byte, salt []byte) error {
	chainMACKey := audit.DeriveChainMACKey(salt)

	scanner := bufio.NewScanner(bytes.NewReader(logBytes))
	var prevComputedHMAC string
	var prevSeq int64
	lineNum := 0

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		lineNum++
		lineBytes := []byte(line)

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			// Malformed line — treat as truncation.
			return ErrChainTruncated
		}

		hdrBytes, decErr := base64.StdEncoding.DecodeString(parts[0])
		if decErr != nil {
			return ErrChainTruncated
		}

		var hdr chainHeader
		if jsonErr := json.Unmarshal(hdrBytes, &hdr); jsonErr != nil {
			return ErrChainTruncated
		}

		// Sequence validation.
		if lineNum == 1 {
			if hdr.Seq != 1 {
				// First entry must have seq=1.
				return ErrChainCorrupted
			}
			expectedPrev := strings.Repeat("0", 32)
			if hdr.PrevHMAC != expectedPrev {
				return ErrChainCorrupted
			}
		} else {
			switch {
			case hdr.Seq < prevSeq:
				// Sequence went backwards.
				return ErrChainReordered
			case hdr.Seq == prevSeq:
				// Duplicate sequence number.
				return ErrChainReordered
			case hdr.Seq > prevSeq+1:
				// Sequence skipped forward — entry was deleted.
				return ErrChainDeleted
			default:
				// hdr.Seq == prevSeq+1: verify HMAC link.
				if hdr.PrevHMAC != prevComputedHMAC {
					return ErrChainCorrupted
				}
			}
		}

		// Advance chain state.
		prevComputedHMAC = audithmac.Of(chainMACKey, lineBytes)
		prevSeq = hdr.Seq
	}

	if err := scanner.Err(); err != nil {
		return ErrChainTruncated
	}

	return nil
}
