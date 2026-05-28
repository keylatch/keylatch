package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

// TailOpts controls the behaviour of Tail.
type TailOpts struct {
	// PollInterval is how often the file is checked for new lines. Default 250ms.
	PollInterval time.Duration
}

// Tail follows the audit log file and sends newly appended events to ch.
// It blocks until ctx is cancelled, seeking to the end of the file on startup.
// Events that cannot be decrypted are silently skipped (log may contain a
// partial line during a concurrent write).
//
// Tail uses a polling strategy to remain dependency-free. The function
// returns nil when ctx is done.
func (l *Logger) Tail(ctx context.Context, opts TailOpts, ch chan<- Event) error {
	interval := opts.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}

	l.mu.Lock()
	// Seek to end so we only emit newly appended events.
	pos, err := l.file.Seek(0, 2 /* io.SeekEnd */)
	l.mu.Unlock()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			pos = l.readNewLines(pos, ch)
		}
	}
}

// readNewLines reads any lines appended to the file since offset pos.
// Returns the new file offset after reading.
// The mutex is released before sending to ch to avoid deadlock when the
// channel buffer fills while the lock is held.
func (l *Logger) readNewLines(pos int64, ch chan<- Event) int64 {
	l.mu.Lock()

	info, err := l.file.Stat()
	if err != nil {
		l.mu.Unlock()
		return pos
	}
	if info.Size() < pos {
		// File was rotated or truncated — reset to start.
		pos = 0
	}
	if info.Size() == pos {
		l.mu.Unlock()
		return pos
	}

	var pending []Event
	newPos := pos

	if _, err := l.file.Seek(pos, 0 /* io.SeekStart */); err == nil {
		scanner := newLineScanner(l.file)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				newPos++
				continue
			}
			newPos += int64(len(line)) + 1 // +1 for newline
			if e, ok := decodeAuditLine(line, l.auditDEK); ok {
				pending = append(pending, e)
			}
		}
		// Restore end-of-file position for normal logging (under lock, touches l.file).
		_, _ = l.file.Seek(0, 2 /* io.SeekEnd */)
	}

	l.mu.Unlock() // release before any channel send

	for _, e := range pending {
		ch <- e
	}
	return newPos
}

// SinceOpts controls the output of Scan.
type SinceOpts struct {
	// Since filters to events at or after this time.
	Since time.Time

	// Agent filters by event's Actor field (HMAC'd value is compared by prefix
	// because callers pass the raw agent name, not the HMAC'd form).
	// When empty no actor filtering is applied.
	Agent string

	// Provider filters by Backend field.
	Provider string

	// Outcome filters by exact Outcome value ("ok", "denied", "error").
	// When empty no outcome filtering is applied.
	Outcome Outcome
}

// Scan reads all events from the audit log that match opts. The log file is
// read from the beginning. DEK must be present in the Logger for decryption.
// Returns the matching events in chronological order.
func (l *Logger) Scan(opts SinceOpts) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Seek(0, 0 /* io.SeekStart */); err != nil {
		return nil, err
	}
	defer func() {
		_, _ = l.file.Seek(0, 2 /* io.SeekEnd */)
	}()

	var results []Event
	scanner := newLineScanner(l.file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		e, ok := decodeAuditLine(line, l.auditDEK)
		if !ok {
			continue
		}

		// Apply time filter.
		if !opts.Since.IsZero() && e.Timestamp.Before(opts.Since) {
			continue
		}
		// Agent filter: e.Actor is HMAC'd, so matching raw plaintext is best-effort
		// (substring match against RuntimeMode provides a usable fallback).
		if opts.Agent != "" && !strings.Contains(e.Actor, opts.Agent) &&
			!strings.Contains(e.RuntimeMode, opts.Agent) {
			continue
		}
		// Apply provider/backend filter.
		if opts.Provider != "" && !strings.EqualFold(e.Backend, opts.Provider) {
			continue
		}
		// Apply outcome filter.
		if opts.Outcome != "" && e.Outcome != opts.Outcome {
			continue
		}
		results = append(results, e)
	}
	return results, nil
}

// Prune removes audit log entries older than cutoff by rewriting the log file.
// It is safe to call concurrently with Log; it takes the logger mutex.
// Returns the number of pruned lines.
func (l *Logger) Prune(cutoff time.Time) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, err := l.file.Seek(0, 0); err != nil {
		return 0, err
	}

	var kept []string
	pruned := 0

	scanner := newLineScanner(l.file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		e, ok := decodeAuditLine(line, l.auditDEK)
		if !ok {
			// Keep lines we cannot decode (may be from a different key term).
			kept = append(kept, line)
			continue
		}
		if e.Timestamp.Before(cutoff) {
			pruned++
			continue
		}
		kept = append(kept, line)
	}

	if pruned == 0 {
		// Seek back to end; nothing to do.
		_, _ = l.file.Seek(0, 2)
		return 0, nil
	}

	// Rewrite: truncate + re-append kept lines.
	if err := l.file.Truncate(0); err != nil {
		_, _ = l.file.Seek(0, 2)
		return 0, err
	}
	if _, err := l.file.Seek(0, 0); err != nil {
		return 0, err
	}
	for _, line := range kept {
		if _, err := l.file.WriteString(line + "\n"); err != nil {
			_, _ = l.file.Seek(0, 2)
			return 0, err
		}
	}
	_ = l.file.Sync()
	_, _ = l.file.Seek(0, 2)

	// Reset chain state to match the last kept line.
	l.seq = 0
	l.prevHMAC = ""
	if err := l.seedChainState(); err != nil {
		return pruned, err
	}

	return pruned, nil
}

// decodeAuditLine decrypts a single audit log line and returns the Event.
// Returns (Event{}, false) on any parse or decryption failure.
func decodeAuditLine(line string, auditDEK []byte) (Event, bool) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) != 2 {
		return Event{}, false
	}
	hdrBytes, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return Event{}, false
	}
	sealed, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(sealed) < 24 {
		return Event{}, false
	}
	nonce := sealed[:24]
	ct := sealed[24:]
	plaintext, err := envelope.Open(envelope.XChaCha20Poly1305, auditDEK, ct, nonce, hdrBytes)
	if err != nil {
		return Event{}, false
	}
	var e Event
	if err := json.Unmarshal(plaintext, &e); err != nil {
		return Event{}, false
	}
	return e, true
}
