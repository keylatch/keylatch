package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/audit/fields"
	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// chainHeader is the unencrypted portion prepended to each audit line.
// It enables HMAC chain verification without the AuditDEK.
type chainHeader struct {
	Seq      int64  `json:"seq"`
	PrevHMAC string `json:"prev_hmac"`
	TS       int64  `json:"ts_unix"` // Unix nanoseconds for fast parsing
}

// appendEvent implements Logger.Log (must hold l.mu): it writes the event and
// rotates once the file passes the size cap.
func (l *Logger) appendEvent(e Event) error {
	if err := l.writeEvent(e); err != nil {
		return err
	}
	if info, err := l.file.Stat(); err == nil && info.Size() > l.maxSize {
		_ = l.rotate() // best-effort; size-cap failure is non-fatal
	}
	return nil
}

// writeEvent seals and appends one event without checking the size cap, so
// rotate can write its sentinels through it without re-entering rotation.
func (l *Logger) writeEvent(e Event) error {
	if l.file == nil {
		return ErrLogClosed
	}

	// Step 1: set timestamp and sequence.
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	seq := l.seq + 1
	prevHMAC := l.prevHMAC
	if prevHMAC == "" && seq == 1 {
		prevHMAC = strings.Repeat("0", 32)
	}

	// Step 2: apply SafeLogFields filtering.
	e.Extra = fields.Redact(l.salt, string(e.Action), e.Extra)

	// Step 3: marshal event to canonical JSON.
	eventJSON, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}

	// Step 4: build chain header.
	hdr := chainHeader{
		Seq:      seq,
		PrevHMAC: prevHMAC,
		TS:       e.Timestamp.UnixNano(),
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		return fmt.Errorf("audit: marshal chain header: %w", err)
	}

	// Step 5: AEAD-seal the event body under the AuditDEK.
	// AAD = chain_header bytes (binds ciphertext to its position in the chain).
	ct, nonce, err := envelope.SealXChaCha20(l.auditDEK, eventJSON, hdrBytes)
	if err != nil {
		return fmt.Errorf("audit: seal event: %w", err)
	}

	// Combine nonce + ciphertext for the sealed blob.
	sealed := make([]byte, len(nonce)+len(ct))
	copy(sealed, nonce)
	copy(sealed[len(nonce):], ct)

	// Step 6: build the on-disk line.
	// Format: base64(chain_header) ' ' base64(nonce||ciphertext) '\n'
	hdrB64 := base64.StdEncoding.EncodeToString(hdrBytes)
	sealedB64 := base64.StdEncoding.EncodeToString(sealed)
	line := hdrB64 + " " + sealedB64 + "\n"
	lineBytes := []byte(line)
	lineForMAC := lineBytes[:len(lineBytes)-1] // exclude trailing newline

	// Step 7: single Write call.
	if _, err := l.file.Write(lineBytes); err != nil {
		return fmt.Errorf("audit: write line: %w", err)
	}

	// Step 8: fsync before returning. Rollback seq/prevHMAC on failure.
	var fsyncErr error
	if l.fsyncFailHook != nil {
		fsyncErr = l.fsyncFailHook()
	} else {
		fsyncErr = l.file.Sync()
	}
	if fsyncErr != nil {
		// Rollback: do not advance chain state.
		return ErrAuditFsyncFailed
	}

	// Step 9: update chain MAC state.
	l.seq = seq
	l.prevHMAC = audithmac.Of(l.chainMACKey, lineForMAC)

	// Step 10: export to SIEM if registered.
	activeExporterOnce.Lock()
	exp := activeExporter
	activeExporterOnce.Unlock()
	if exp != nil {
		exp.Export([]byte(line))
	}

	return nil
}

// seedChainState reads the last line of the current log to restore seq/prevHMAC.
// Called once from Open, before any writes.
func (l *Logger) seedChainState() error {
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() == 0 {
		// Empty file — fresh start.
		l.seq = 0
		l.prevHMAC = ""
		return nil
	}

	// Read the last line.
	lastLine, err := readLastLine(l.file)
	if err != nil {
		return fmt.Errorf("audit: seed chain state: %w", err)
	}

	parts := strings.SplitN(strings.TrimRight(lastLine, "\n"), " ", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w: malformed last line", ErrLogCorrupt)
	}

	hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("%w: decode chain header: %v", ErrLogCorrupt, err)
	}

	var hdr chainHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return fmt.Errorf("%w: parse chain header: %v", ErrLogCorrupt, err)
	}

	lineForMAC := []byte(strings.TrimRight(lastLine, "\n"))
	l.seq = hdr.Seq
	l.prevHMAC = audithmac.Of(l.chainMACKey, lineForMAC)
	return nil
}

// readLastLine reads the last non-empty line from f using a backward scan.
func readLastLine(f *os.File) (string, error) {
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	size := info.Size()
	if size == 0 {
		return "", nil
	}

	const chunkSize = 4096
	buf := make([]byte, 0, chunkSize)
	pos := size

	for pos > 0 {
		readSize := int64(chunkSize)
		if pos < readSize {
			readSize = pos
		}
		pos -= readSize
		chunk := make([]byte, readSize)
		if _, err := f.ReadAt(chunk, pos); err != nil && err != io.EOF {
			return "", err
		}
		buf = append(chunk, buf...)
		// Look for a newline not at the very end.
		content := bytes.TrimRight(buf, "\n")
		if idx := bytes.LastIndexByte(content, '\n'); idx >= 0 {
			return string(buf[idx+1:]), nil
		}
		if pos == 0 {
			return string(buf), nil
		}
	}
	return string(buf), nil
}

// summarize implements Summarize (must hold l.mu).
func (l *Logger) summarize(opts SummaryOpts) (Summary, error) {
	// Seek to start for reading.
	if _, err := l.file.Seek(0, io.SeekStart); err != nil {
		return Summary{}, err
	}
	defer func() {
		// Seek back to end for appending.
		_, _ = l.file.Seek(0, io.SeekEnd)
	}()

	sum := Summary{
		ByAction:  make(map[Action]int),
		ByOutcome: make(map[Outcome]int),
	}
	seenAccessors := make(map[string]bool)

	scanner := newLineScanner(l.file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
		if err != nil {
			continue
		}

		sealed, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil || len(sealed) < 24 {
			continue
		}
		nonce := sealed[:24]
		ct := sealed[24:]

		plaintext, err := openSealed(l.keys(), ct, nonce, hdrBytes)
		if err != nil {
			continue
		}

		var e Event
		if err := json.Unmarshal(plaintext, &e); err != nil {
			continue
		}

		// Apply filters.
		if !opts.Since.IsZero() && e.Timestamp.Before(opts.Since) {
			continue
		}
		if opts.Path != "" && e.Path != opts.Path {
			continue
		}
		if opts.Action != "" && e.Action != opts.Action {
			continue
		}
		if opts.Service != "" && e.ServiceName != opts.Service {
			continue
		}

		sum.TotalEvents++
		sum.ByAction[e.Action]++
		sum.ByOutcome[e.Outcome]++

		if sum.OldestEvent.IsZero() || e.Timestamp.Before(sum.OldestEvent) {
			sum.OldestEvent = e.Timestamp
		}
		if e.Timestamp.After(sum.NewestEvent) {
			sum.NewestEvent = e.Timestamp
		}
		if e.Accessor != "" && !seenAccessors[e.Accessor] {
			seenAccessors[e.Accessor] = true
			sum.AccessorHMACs = append(sum.AccessorHMACs, e.Accessor)
		}
	}
	return sum, nil
}

// rotate moves the current file to generation .1 (must hold l.mu).
//
// The old file ends with a rotation sentinel and the new file starts with a
// rotation-continued sentinel whose prev_file_hmac is the HMAC of that last
// line, so the chain can be verified across files. Older generations shift up
// by one and the oldest beyond retainFiles is removed.
func (l *Logger) rotate() error {
	if l.file == nil {
		return ErrLogClosed
	}
	rotated := rotatedName(l.path, 1)

	_ = l.writeEvent(Event{ // best-effort; a failure here does not abort rotation
		Timestamp: time.Now(),
		Action:    ActionAuditRotate,
		Outcome:   OutcomeOK,
		Extra:     map[string]any{"rotated_to": rotated},
	})
	prevHMACForNewFile := l.prevHMAC

	_ = l.file.Sync()
	_ = l.file.Close()
	l.file = nil

	if err := shiftGenerations(l.path, l.retainFiles); err != nil {
		l.reopen()
		return err
	}
	if err := os.Rename(l.path, rotated); err != nil {
		l.reopen()
		return fmt.Errorf("audit: rotate rename: %w", err)
	}

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open new log after rotate: %w", err)
	}
	l.file = f
	l.seq = 0
	l.prevHMAC = ""

	_ = l.writeEvent(Event{ // best-effort; the new file is already in place
		Timestamp: time.Now(),
		Action:    ActionAuditRotate,
		Outcome:   OutcomeOK,
		Extra: map[string]any{
			"rotated_from":   rotated,
			"prev_file_hmac": prevHMACForNewFile,
		},
	})
	return nil
}

// reopen restores the current file after a failed rotation, keeping the
// chain state so later events still link to the existing lines.
func (l *Logger) reopen() {
	if f, err := os.OpenFile(l.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600); err == nil {
		l.file = f
	}
}

func rotatedName(path string, generation int) string {
	return path + "." + strconv.Itoa(generation)
}

// shiftGenerations renames path.N to path.N+1 for every kept generation,
// dropping the oldest so at most retain rotated files remain.
func shiftGenerations(path string, retain int) error {
	if retain < 1 {
		retain = 1
	}
	if err := os.Remove(rotatedName(path, retain)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("audit: remove oldest generation: %w", err)
	}
	for g := retain - 1; g >= 1; g-- {
		err := os.Rename(rotatedName(path, g), rotatedName(path, g+1))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("audit: shift generation %d: %w", g, err)
		}
	}
	return nil
}

// lineScanner provides a simple line-by-line scanner over an io.Reader.
type lineScanner struct {
	r   io.Reader
	buf []byte
	err error
	cur string
}

func newLineScanner(r io.Reader) *lineScanner {
	return &lineScanner{r: r}
}

func (s *lineScanner) Scan() bool {
	for {
		if idx := bytes.IndexByte(s.buf, '\n'); idx >= 0 {
			s.cur = string(s.buf[:idx])
			s.buf = s.buf[idx+1:]
			return true
		}
		if s.err != nil {
			if len(s.buf) > 0 {
				s.cur = string(s.buf)
				s.buf = nil
				return true
			}
			return false
		}
		chunk := make([]byte, 4096)
		n, err := s.r.Read(chunk)
		if n > 0 {
			s.buf = append(s.buf, chunk[:n]...)
		}
		if err != nil {
			s.err = err
		}
	}
}

func (s *lineScanner) Text() string { return s.cur }
