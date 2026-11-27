package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func logN(t *testing.T, l *Logger, n int) {
	t.Helper()
	for range n {
		if err := l.Log(context.Background(), Event{Action: ActionRun, Outcome: OutcomeOK, Extra: map[string]any{"connection": "c"}}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHeadMatchesLogger(t *testing.T) {
	l, path, seed := openSmallLog(t, 1<<20, 5)
	logN(t, l, 4)
	got, err := ReadHead(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	want := l.Head()
	if got.Seq != 4 || got.Seq != want.Seq || got.Hash != want.Hash || got.KeyID != want.KeyID || got.KeyID != KeyID(seed) {
		t.Fatalf("ReadHead = %+v, logger head = %+v", got, want)
	}
	raw, _ := json.Marshal(got)
	var shape map[string]any
	_ = json.Unmarshal(raw, &shape)
	for _, k := range []string{"seq", "hash", "time", "key_id"} {
		if _, ok := shape[k]; !ok {
			t.Errorf("head JSON lacks %q: %s", k, raw)
		}
	}
	if len(shape) != 4 {
		t.Errorf("head JSON has extra fields: %s", raw)
	}
}

// A log cut back after an anchor was taken fails against that anchor, and so
// does a log whose tail was replaced; an untouched or grown log passes.
func TestVerifyDetectsTruncationAgainstAnchor(t *testing.T) {
	l, path, seed := openSmallLog(t, 1<<20, 5)
	logN(t, l, 6)
	anchor, err := ReadHead(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAnchor(path, seed, anchor); err != nil {
		t.Fatalf("fresh anchor: %v", err)
	}
	logN(t, l, 2)
	if err := VerifyAnchor(path, seed, anchor); err != nil {
		t.Fatalf("anchor after the log grew: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	// The attacker keeps the first 4 lines: a chain that still verifies.
	if err := os.WriteFile(path, []byte(strings.Join(lines[:4], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAnchor(path, seed, anchor); !errors.Is(err, ErrAnchorNotFound) {
		t.Fatalf("truncated log passed the anchor: %v", err)
	}

	if err := VerifyAnchor(path, seed, Head{Seq: anchor.Seq, Hash: anchor.Hash, KeyID: "0000000000000000"}); !errors.Is(err, ErrAnchorKeyMismatch) {
		t.Fatalf("anchor from another key: %v", err)
	}
}

func TestExportVerifiesChain(t *testing.T) {
	l, path, seed := openSmallLog(t, 1<<20, 5)
	dek := l.auditDEK
	start := time.Now().Add(-time.Minute)
	logN(t, l, 5)

	got, err := Export(path, seed, dek, nil, ExportOpts{Since: start, Until: time.Now().Add(time.Minute)})
	if err != nil || len(got) != 5 {
		t.Fatalf("export: %v, %d events", err, len(got))
	}
	for i, e := range got {
		if e.Seq != int64(i+1) || e.Hash == "" || e.Event.Action != ActionRun {
			t.Fatalf("event %d = %+v", i, e)
		}
	}
	if none, err := Export(path, seed, dek, nil, ExportOpts{Since: time.Now().Add(time.Hour)}); err != nil || len(none) != 0 {
		t.Fatalf("range after the log: %v, %d events", err, len(none))
	}
	// An export leaves the log verifiable.
	if r, err := VerifyChain(path, seed, dek); err != nil || r.FirstBadLine != 0 {
		t.Fatalf("log after export: %v %+v", err, r)
	}

	// A line removed from the middle breaks the chain: nothing is exported.
	data, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(data), "\n")
	tampered := strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "")
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := Export(path, seed, dek, nil, ExportOpts{}); !errors.Is(err, ErrChainBroken) || len(got) != 0 {
		t.Fatalf("tampered export: %v, %d events", err, len(got))
	}
}

func TestExportSpansRotatedFiles(t *testing.T) {
	l, path, seed := openSmallLog(t, 1<<20, 5)
	logN(t, l, 2)
	if err := l.Rotate(); err != nil {
		t.Fatal(err)
	}
	logN(t, l, 2)
	got, err := Export(path, seed, l.auditDEK, nil, ExportOpts{})
	if err != nil {
		t.Fatal(err)
	}
	// Two events and the rotation marker in the old file, the continuation
	// marker and two events in the new one.
	if len(got) != 6 {
		t.Fatalf("exported %d events across a rotation, want 6", len(got))
	}
	if got[0].File != "audit.log.1" || got[len(got)-1].File != "audit.log" {
		t.Fatalf("files in order: %s ... %s", got[0].File, got[len(got)-1].File)
	}
}

// The head hash reaches the OS log sink after every AnchorEvery-th event and
// on demand, never carrying more than the head.
func TestOSLogAnchorWritten(t *testing.T) {
	l, path, seed := openSmallLog(t, 1<<30, 5)
	var got []Head
	l.SetAnchorSink(func(h Head) error { got = append(got, h); return nil })

	logN(t, l, AnchorEvery-1)
	if len(got) != 0 {
		t.Fatalf("anchored after %d events", AnchorEvery-1)
	}
	logN(t, l, 1)
	if len(got) != 1 || got[0].Seq != AnchorEvery {
		t.Fatalf("anchors after %d events: %+v", AnchorEvery, got)
	}
	head, err := ReadHead(path, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Hash != head.Hash || got[0].KeyID != head.KeyID {
		t.Fatalf("anchor %+v does not match the log head %+v", got[0], head)
	}
	if err := VerifyAnchor(path, seed, got[0]); err != nil {
		t.Fatalf("anchor written to the OS log does not verify: %v", err)
	}

	if err := l.Anchor(); err != nil || len(got) != 2 {
		t.Fatalf("explicit anchor: %v, %d anchors", err, len(got))
	}
	msg := anchorMessage(got[1])
	for _, want := range []string{"seq=", "hash=" + got[1].Hash, "key_id=" + got[1].KeyID} {
		if !strings.Contains(msg, want) {
			t.Errorf("anchor message %q lacks %q", msg, want)
		}
	}
	if anchorIdentifier != "keylatch-audit" {
		t.Fatalf("anchor identifier %q", anchorIdentifier)
	}
}
