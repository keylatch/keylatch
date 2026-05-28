package audit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// ChainReport summarizes the result of a VerifyChain call.
type ChainReport struct {
	TotalLines     int
	Verified       int
	FirstBadLine   int // 1-based; 0 means no bad lines found
	FirstBadReason string
}

// VerifyChain verifies the HMAC chain integrity of the audit log at path.
//
// Dual-mode per FIND3-008:
//   - auditDEK == nil: header-only mode (no AEAD; chain integrity only).
//   - auditDEK != nil: full mode (AEAD-open each event body + chain check).
//
// salt is the 32-byte HMAC salt used to derive the chain MAC key.
func VerifyChain(path string, salt []byte, auditDEK []byte) (ChainReport, error) {
	// Derive chainMACKey from salt only (matches Logger.Open / DeriveChainMACKey).
	// This key is DEK-independent so VerifyChain works in header-only mode (FIND3-008).
	chainMACKey := DeriveChainMACKey(salt)

	f, err := os.Open(path)
	if err != nil {
		return ChainReport{}, fmt.Errorf("audit: open log: %w", err)
	}
	defer f.Close() //nolint:errcheck // defer close, error non-actionable after file is opened for reading

	report := ChainReport{}
	var prevComputedHMAC string
	var prevSeq int64

	scanner := newLineScanner(f)
	lineNum := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		lineNum++
		report.TotalLines++

		lineBytes := []byte(line)
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			if report.FirstBadLine == 0 {
				report.FirstBadLine = lineNum
				report.FirstBadReason = "malformed line (no space separator)"
			}
			prevComputedHMAC = audithmac.Of(chainMACKey, lineBytes)
			continue
		}

		hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			if report.FirstBadLine == 0 {
				report.FirstBadLine = lineNum
				report.FirstBadReason = fmt.Sprintf("base64 decode header: %v", err)
			}
			prevComputedHMAC = audithmac.Of(chainMACKey, lineBytes)
			continue
		}

		var hdr chainHeader
		if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
			if report.FirstBadLine == 0 {
				report.FirstBadLine = lineNum
				report.FirstBadReason = fmt.Sprintf("parse chain header: %v", err)
			}
			prevComputedHMAC = audithmac.Of(chainMACKey, lineBytes)
			continue
		}

		// Sequence and chain HMAC validation.
		var lineBad bool
		if lineNum == 1 {
			if hdr.Seq != 1 {
				if report.FirstBadLine == 0 {
					report.FirstBadLine = lineNum
					report.FirstBadReason = fmt.Sprintf("first line seq=%d, want 1", hdr.Seq)
				}
				lineBad = true
			}
			expectedPrev := strings.Repeat("0", 32)
			if !lineBad && hdr.PrevHMAC != expectedPrev {
				if report.FirstBadLine == 0 {
					report.FirstBadLine = lineNum
					report.FirstBadReason = "first line prev_hmac must be 32 zeros"
				}
				lineBad = true
			}
		} else {
			if hdr.Seq != prevSeq+1 {
				if report.FirstBadLine == 0 {
					report.FirstBadLine = lineNum
					report.FirstBadReason = fmt.Sprintf("seq gap: got %d, want %d", hdr.Seq, prevSeq+1)
				}
				lineBad = true
			}
			if !lineBad && hdr.PrevHMAC != prevComputedHMAC {
				if report.FirstBadLine == 0 {
					report.FirstBadLine = lineNum
					report.FirstBadReason = "chain HMAC mismatch"
				}
				lineBad = true
			}
		}

		// Full verification mode: AEAD-open the event body.
		if !lineBad && auditDEK != nil {
			sealed, err := base64.StdEncoding.DecodeString(parts[1])
			if err != nil || len(sealed) < 24 {
				if report.FirstBadLine == 0 {
					report.FirstBadLine = lineNum
					report.FirstBadReason = "base64 decode sealed body failed"
				}
				lineBad = true
			} else {
				nonce := sealed[:24]
				ct := sealed[24:]
				if _, err := envelope.Open(envelope.XChaCha20Poly1305, auditDEK, ct, nonce, hdrBytes); err != nil {
					if report.FirstBadLine == 0 {
						report.FirstBadLine = lineNum
						report.FirstBadReason = "AEAD authentication failed"
					}
					lineBad = true
				}
			}
		}

		if !lineBad {
			report.Verified++
		}

		// Advance chain state.
		prevComputedHMAC = audithmac.Of(chainMACKey, lineBytes)
		prevSeq = hdr.Seq
	}

	return report, nil
}
