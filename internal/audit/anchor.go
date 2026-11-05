package audit

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	audithmac "github.com/keylatch/keylatch/internal/audit/hmac"
)

// AnchorEvery is how many events pass between head hashes written to the OS
// log.
const AnchorEvery = 1000

// Head identifies the end of a log: the sequence number and chain hash of its
// last line. A copy kept outside the log (an anchor) lets a later verification
// notice that events were removed from the end.
type Head struct {
	Seq   int64     `json:"seq"`
	Hash  string    `json:"hash"`
	Time  time.Time `json:"time"`
	KeyID string    `json:"key_id"`
}

// Anchor errors.
var (
	// ErrAnchorNotFound means no line of the log has the anchor's sequence
	// number and hash: events were removed, or the log is not the anchored one.
	ErrAnchorNotFound = errors.New("audit: anchor is not in the log")
	// ErrAnchorKeyMismatch means the anchor was taken under a different chain
	// key than the one verifying it.
	ErrAnchorKeyMismatch = errors.New("audit: anchor was taken under a different key")
	// ErrChainBroken means the log's chain does not verify.
	ErrChainBroken = errors.New("audit: chain does not verify")
)

// keyID names a chain key without revealing it.
func keyID(macKey []byte) string {
	sum := sha256.Sum256(append([]byte("keylatch/audit/key-id\x00"), macKey...))
	return hex.EncodeToString(sum[:8])
}

// KeyID returns the identifier of the chain key derived from seed.
func KeyID(seed []byte) string { return keyID(DeriveChainMACKey(seed)) }

// Head returns the head of the live log as the logger knows it.
func (l *Logger) Head() Head {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.head(time.Now().UTC())
}

func (l *Logger) head(at time.Time) Head {
	return Head{Seq: l.seq, Hash: l.prevHMAC, Time: at, KeyID: keyID(l.chainMACKey)}
}

// SetAnchorSink sets where head hashes go: every AnchorEvery events and on
// each Anchor call. A failing sink never fails a write.
func (l *Logger) SetAnchorSink(sink func(Head) error) {
	l.mu.Lock()
	l.anchorSink = sink
	l.mu.Unlock()
}

// Anchor writes the current head to the anchor sink.
func (l *Logger) Anchor() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.anchorSink == nil || l.seq == 0 {
		return nil
	}
	return l.anchorSink(l.head(time.Now().UTC()))
}

// anchorIfDue writes the head after every AnchorEvery-th event (must hold
// l.mu).
func (l *Logger) anchorIfDue(at time.Time) {
	if l.anchorSink == nil || l.seq%AnchorEvery != 0 {
		return
	}
	if err := l.anchorSink(l.head(at)); err != nil {
		slog.Warn("audit anchor was not written to the OS log", "error", err)
	}
}

// ReadHead returns the head of the log at path without verifying it. seed is
// the chain seed the log was written with.
func ReadHead(path string, seed []byte) (Head, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the configured audit log
	if err != nil {
		return Head{}, fmt.Errorf("audit: open log: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	macKey := DeriveChainMACKey(seed)
	line, err := readLastLine(f)
	if err != nil {
		return Head{}, fmt.Errorf("audit: read head: %w", err)
	}
	line = strings.TrimRight(line, "\n")
	if line == "" {
		return Head{KeyID: keyID(macKey)}, nil
	}
	hdr, err := parseHeader(line)
	if err != nil {
		return Head{}, fmt.Errorf("%w: %v", ErrLogCorrupt, err)
	}
	return Head{
		Seq:   hdr.Seq,
		Hash:  audithmac.Of(macKey, []byte(line)),
		Time:  time.Unix(0, hdr.TS).UTC(),
		KeyID: keyID(macKey),
	}, nil
}

func parseHeader(line string) (chainHeader, error) {
	var hdr chainHeader
	b64, _, ok := strings.Cut(line, " ")
	if !ok {
		return hdr, errors.New("malformed line")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return hdr, err
	}
	return hdr, json.Unmarshal(raw, &hdr)
}

// VerifyAnchor checks that the log at path verifies and that the line the
// anchor names is in it with the hash the anchor recorded. The live file is
// searched first, then rotated generations, because sequence numbers restart
// in each file. A log truncated after the anchor was taken fails with
// ErrAnchorNotFound.
func VerifyAnchor(path string, seed []byte, a Head) error {
	macKey := DeriveChainMACKey(seed)
	if a.KeyID != "" && a.KeyID != keyID(macKey) {
		return ErrAnchorKeyMismatch
	}
	for _, p := range logFamily(path) {
		found, err := fileHasLine(p, macKey, a)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		report, err := VerifyChain(p, seed, nil)
		if err != nil {
			return err
		}
		if report.FirstBadLine != 0 {
			return fmt.Errorf("%w: %s line %d: %s", ErrChainBroken, p, report.FirstBadLine, report.FirstBadReason)
		}
		return nil
	}
	return ErrAnchorNotFound
}

// logFamily lists the live log followed by its rotated generations, newest
// first, skipping missing files.
func logFamily(path string) []string {
	out := []string{path}
	for g := 1; ; g++ {
		p := rotatedName(path, g)
		if _, err := os.Stat(p); err != nil {
			return out
		}
		out = append(out, p)
	}
}

func fileHasLine(path string, macKey []byte, a Head) (bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the configured audit log
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: open log: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	sc := newLineScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		hdr, err := parseHeader(line)
		if err != nil || hdr.Seq != a.Seq {
			continue
		}
		if audithmac.Of(macKey, []byte(line)) == a.Hash {
			return true, nil
		}
	}
	return false, nil
}

// ExportOpts selects the events Export writes.
type ExportOpts struct {
	// Since and Until bound the event time; zero values leave that side open.
	Since, Until time.Time
}

// ExportedEvent is one line of an export: the event with its position and
// chain hash, so the export can be matched against the log and anchors.
type ExportedEvent struct {
	File  string `json:"file"`
	Seq   int64  `json:"seq"`
	Hash  string `json:"hash"`
	Event Event  `json:"event"`
}

// Export verifies the chain of every log file that can hold events in the
// range and returns the matching events oldest first, decrypted with dek (and
// olderDEKs). No event is returned when any examined file fails verification.
func Export(path string, seed, dek []byte, olderDEKs [][]byte, opts ExportOpts) ([]ExportedEvent, error) {
	macKey := DeriveChainMACKey(seed)
	keys := append([][]byte{dek}, olderDEKs...)
	family := logFamily(path)

	var out []ExportedEvent
	for i := len(family) - 1; i >= 0; i-- {
		p := family[i]
		if skipByAge(p, opts.Since) {
			continue
		}
		report, err := VerifyChain(p, seed, dek, olderDEKs...)
		if err != nil {
			return nil, err
		}
		if report.FirstBadLine != 0 {
			return nil, fmt.Errorf("%w: %s line %d: %s", ErrChainBroken, p, report.FirstBadLine, report.FirstBadReason)
		}
		events, err := readExport(p, macKey, keys, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, events...)
	}
	return out, nil
}

// skipByAge reports whether a rotated file was last written before since, so
// it cannot hold events in the range.
func skipByAge(path string, since time.Time) bool {
	if since.IsZero() {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.ModTime().Before(since)
}

func readExport(path string, macKey []byte, keys [][]byte, opts ExportOpts) ([]ExportedEvent, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the configured audit log
	if err != nil {
		return nil, fmt.Errorf("audit: open log: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	var out []ExportedEvent
	sc := newLineScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		hdr, err := parseHeader(line)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrLogCorrupt, err)
		}
		e, ok := decodeAuditLine(line, keys)
		if !ok {
			return nil, fmt.Errorf("%w: %s seq %d cannot be decrypted", ErrLogCorrupt, path, hdr.Seq)
		}
		if (!opts.Since.IsZero() && e.Timestamp.Before(opts.Since)) || (!opts.Until.IsZero() && e.Timestamp.After(opts.Until)) {
			continue
		}
		out = append(out, ExportedEvent{File: baseName(path), Seq: hdr.Seq, Hash: audithmac.Of(macKey, []byte(line)), Event: e})
	}
	return out, nil
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
