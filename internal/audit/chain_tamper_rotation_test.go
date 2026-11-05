package audit

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/keylatch/keylatch/internal/crypto/envelope"
)

type scLog struct {
	l    *Logger
	path string
	salt []byte
	dek  []byte
}

func scOpen(t *testing.T) *scLog {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "auditlogs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, 32)
	dek := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 3)
		dek[i] = byte(200 - i)
	}
	path := filepath.Join(dir, "audit.log")
	l, err := Open(path, salt, dek)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &scLog{l: l, path: path, salt: salt, dek: dek}
}

func (s *scLog) log(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := s.l.Log(context.Background(), Event{Action: ActionRead, Outcome: OutcomeOK, Path: "p/" + string(rune('a'+i))}); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
}

func scLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

func scWriteLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func scAppendRaw(t *testing.T, path, raw string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if _, err := f.WriteString(raw); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyChain_DetectsBodyTamperInHeaderOnlyMode(t *testing.T) {
	s := scOpen(t)
	s.log(t, 4)
	lines := scLines(t, s.path)

	// Replace line 2's sealed body with a validly sealed different event under
	// the same header: AEAD passes with the DEK, but the chain MAC of line 2
	// no longer matches line 3's prev_hmac.
	parts := strings.SplitN(lines[1], " ", 2)
	hdr, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	forged, _ := json.Marshal(Event{Action: ActionRead, Outcome: OutcomeOK, Path: "forged"})
	ct, nonce, err := envelope.SealXChaCha20(s.dek, forged, hdr)
	if err != nil {
		t.Fatal(err)
	}
	lines[1] = parts[0] + " " + base64.StdEncoding.EncodeToString(append(nonce, ct...))
	scWriteLines(t, s.path, lines)

	for _, dek := range [][]byte{nil, s.dek} {
		rep, err := VerifyChain(s.path, s.salt, dek)
		if err != nil {
			t.Fatal(err)
		}
		if rep.FirstBadLine != 3 || rep.FirstBadReason != "chain HMAC mismatch" {
			t.Fatalf("dek=%v: report %+v", dek != nil, rep)
		}
		if rep.TotalLines != 4 || rep.Verified != 3 {
			t.Fatalf("dek=%v: counts %+v", dek != nil, rep)
		}
	}
}

func TestVerifyChain_WrongSaltFailsChain(t *testing.T) {
	s := scOpen(t)
	s.log(t, 3)
	wrong := make([]byte, 32)
	rep, err := VerifyChain(s.path, wrong, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FirstBadLine != 2 || rep.FirstBadReason != "chain HMAC mismatch" {
		t.Fatalf("report %+v", rep)
	}
}

func TestVerifyChain_IgnoresBlankLines(t *testing.T) {
	s := scOpen(t)
	s.log(t, 2)
	lines := scLines(t, s.path)
	scWriteLines(t, s.path, []string{lines[0], "", lines[1], ""})
	rep, err := VerifyChain(s.path, s.salt, s.dek)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FirstBadLine != 0 || rep.Verified != 2 || rep.TotalLines != 2 {
		t.Fatalf("report %+v", rep)
	}
}

func TestRotate_RenameFailureKeepsLoggerUsable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	s := scOpen(t)
	s.log(t, 1)
	dir := filepath.Dir(s.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := s.l.Rotate()
	if err == nil || !strings.Contains(err.Error(), "rotate rename") {
		t.Fatalf("want rotate rename error, got %v", err)
	}
	s.log(t, 1)
	rep, err := VerifyChain(s.path, s.salt, s.dek)
	if err != nil {
		t.Fatal(err)
	}
	if rep.FirstBadLine != 0 || rep.TotalLines != 3 {
		t.Fatalf("chain after failed rotate: %+v", rep)
	}
}

func TestLog_FailuresDoNotAdvanceChain(t *testing.T) {
	t.Run("seal failure with bad dek", func(t *testing.T) {
		s := scOpen(t)
		s.l.auditDEK = make([]byte, 16)
		err := s.l.Log(context.Background(), Event{Action: ActionRead})
		if err == nil || !strings.Contains(err.Error(), "seal event") {
			t.Fatalf("want seal error, got %v", err)
		}
		if s.l.seq != 0 {
			t.Fatalf("seq advanced to %d", s.l.seq)
		}
	})

	t.Run("unmarshalable extra", func(t *testing.T) {
		s := scOpen(t)
		err := s.l.Log(context.Background(), Event{Action: ActionGatewayCall, Extra: map[string]any{"reason": make(chan int)}})
		if err == nil || !strings.Contains(err.Error(), "marshal event") {
			t.Fatalf("want marshal error, got %v", err)
		}
	})

	t.Run("closed logger", func(t *testing.T) {
		s := scOpen(t)
		s.log(t, 1)
		if err := s.l.Close(); err != nil {
			t.Fatal(err)
		}
		if err := s.l.Close(); err != nil {
			t.Fatalf("second close: %v", err)
		}
		if err := s.l.Log(context.Background(), Event{Action: ActionRead}); err == nil || !strings.Contains(err.Error(), "log closed") {
			t.Fatalf("Log after close: %v", err)
		}
		if s.l.seq != 1 {
			t.Fatalf("seq = %d, want 1", s.l.seq)
		}
		if _, err := s.l.Scan(SinceOpts{}); err == nil {
			t.Fatal("Scan after close succeeded")
		}
		if _, err := s.l.Summarize(SummaryOpts{}); err == nil {
			t.Fatal("Summarize after close succeeded")
		}
		if _, err := s.l.Prune(time.Now()); err == nil {
			t.Fatal("Prune after close succeeded")
		}
		if err := s.l.Tail(context.Background(), TailOpts{}, make(chan Event)); err == nil {
			t.Fatal("Tail after close succeeded")
		}
		if got := s.l.readNewLines(5, make(chan Event)); got != 5 {
			t.Fatalf("readNewLines on closed file moved offset to %d", got)
		}
	})
}

func TestOpen_FailureModes(t *testing.T) {
	base := t.TempDir()
	if _, err := Open(filepath.Join(base, "missing", "audit.log"), make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("Open in missing directory succeeded")
	}

	dir := filepath.Join(base, "logs")
	if err := os.MkdirAll(filepath.Join(dir, "audit.log"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "audit.log"), make([]byte, 32), make([]byte, 32)); err == nil {
		t.Fatal("Open on directory path succeeded")
	}

	corrupt := filepath.Join(dir, "corrupt.log")
	hdr := base64.StdEncoding.EncodeToString([]byte("not json"))
	if err := os.WriteFile(corrupt, []byte(hdr+" AAAA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(corrupt, make([]byte, 32), make([]byte, 32)); !errors.Is(err, ErrLogCorrupt) {
		t.Fatalf("want ErrLogCorrupt, got %v", err)
	}
}

func TestReadLastLine_EmptyAndLongLines(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	if got, err := readLastLine(f); err != nil || got != "" {
		t.Fatalf("empty: %q %v", got, err)
	}
	long := strings.Repeat("b", 9000)
	if _, err := f.WriteString("first\n" + long + "\n"); err != nil {
		t.Fatal(err)
	}
	got, err := readLastLine(f)
	if err != nil || got != long+"\n" {
		t.Fatalf("long last line: len=%d err=%v", len(got), err)
	}
}

func scForeignLines(t *testing.T, dek []byte) []string {
	t.Helper()
	hdr := []byte(`{"seq":99,"prev_hmac":"x","ts_unix":1}`)
	hdrB64 := base64.StdEncoding.EncodeToString(hdr)
	ct, nonce, err := envelope.SealXChaCha20(dek, []byte("not json"), hdr)
	if err != nil {
		t.Fatal(err)
	}
	return []string{
		"no-separator",
		"!!! " + base64.StdEncoding.EncodeToString([]byte("x")),
		hdrB64 + " !!!",
		hdrB64 + " " + base64.StdEncoding.EncodeToString([]byte("short")),
		hdrB64 + " " + base64.StdEncoding.EncodeToString(append(nonce, ct...)),
	}
}

func TestReaders_SkipUndecodableLines(t *testing.T) {
	s := scOpen(t)
	s.log(t, 1)
	other := make([]byte, 32)
	foreign := scForeignLines(t, s.dek)
	otherKey := scForeignLines(t, other)[4]
	scAppendRaw(t, s.path, "\n"+strings.Join(foreign, "\n")+"\n"+otherKey+"\n")
	if err := s.l.Log(context.Background(), Event{Action: ActionWrite, Outcome: OutcomeDenied}); err != nil {
		t.Fatal(err)
	}

	evs, err := s.l.Scan(SinceOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("Scan events = %d, want 2", len(evs))
	}

	sum, err := s.l.Summarize(SummaryOpts{Action: ActionWrite})
	if err != nil {
		t.Fatal(err)
	}
	if sum.TotalEvents != 1 || sum.ByOutcome[OutcomeDenied] != 1 {
		t.Fatalf("summary %+v", sum)
	}
}

func TestPrune_KeepsUndecodableLinesAndReseedsChain(t *testing.T) {
	s := scOpen(t)
	if err := s.l.Log(context.Background(), Event{Action: ActionRead, Timestamp: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	foreign := scForeignLines(t, make([]byte, 32))[4]
	scAppendRaw(t, s.path, "\n"+foreign+"\n")
	s.log(t, 1)

	n, err := s.l.Prune(time.Now().Add(-24 * time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
	lines := scLines(t, s.path)
	if len(lines) != 2 || lines[0] != foreign {
		t.Fatalf("after prune lines = %q", lines)
	}
	s.log(t, 1)
	evs, err := s.l.Scan(SinceOpts{})
	if err != nil || len(evs) != 2 {
		t.Fatalf("events after prune: %d %v", len(evs), err)
	}
}

func TestPrune_TempFileFailureLeavesLogIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	s := scOpen(t)
	if err := s.l.Log(context.Background(), Event{Action: ActionRead, Timestamp: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	s.log(t, 1)
	before, _ := os.ReadFile(s.path)
	dir := filepath.Dir(s.path)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if _, err := s.l.Prune(time.Now().Add(-time.Hour)); err == nil {
		t.Fatal("Prune succeeded without a writable directory")
	}
	after, _ := os.ReadFile(s.path)
	if string(before) != string(after) {
		t.Fatal("log modified by failed prune")
	}
	s.log(t, 1)
}

func TestReadNewLines_ResetsAfterTruncationAndSkipsBlankLines(t *testing.T) {
	s := scOpen(t)
	s.log(t, 3)
	st, err := os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	pos := st.Size()

	if n, err := s.l.Prune(time.Now().Add(time.Hour)); err != nil || n != 3 {
		t.Fatalf("Prune all = %d, %v", n, err)
	}
	scAppendRaw(t, s.path, "\n")
	if err := s.l.Log(context.Background(), Event{Action: ActionWrite, Path: "after-truncate"}); err != nil {
		t.Fatal(err)
	}

	ch := make(chan Event, 4)
	newPos := s.l.readNewLines(pos, ch)
	close(ch)
	var got []Event
	for e := range ch {
		got = append(got, e)
	}
	if len(got) != 1 || got[0].Path != "after-truncate" {
		t.Fatalf("delivered %+v", got)
	}
	st, err = os.Stat(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if newPos != st.Size() {
		t.Fatalf("offset = %d, want %d", newPos, st.Size())
	}
	if again := s.l.readNewLines(newPos, make(chan Event)); again != newPos {
		t.Fatalf("no-op read moved offset to %d", again)
	}
}

func TestTail_DefaultIntervalStopsOnCancel(t *testing.T) {
	s := scOpen(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.l.Tail(ctx, TailOpts{}, make(chan Event)) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Tail did not stop")
	}
}

func TestRetentionSweep_RemovesOnlyOldNonActiveFiles(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	old := time.Now().Add(-90 * 24 * time.Hour)
	for _, name := range []string{"audit.log", "audit.log.1", "fresh.log.1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"audit.log", "audit.log.1"} {
		if err := os.Chtimes(filepath.Join(dir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "subdir"), old, old); err != nil {
		t.Fatal(err)
	}

	if err := RunAuditRetentionSweep(logPath, 30); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.1")); !os.IsNotExist(err) {
		t.Fatal("old rotated file not removed")
	}
	for _, keep := range []string{"audit.log", "fresh.log.1", "subdir"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Fatalf("%s removed: %v", keep, err)
		}
	}

	if err := RunAuditRetentionSweep(filepath.Join(dir, "missing", "audit.log"), 30); err == nil {
		t.Fatal("missing dir sweep succeeded")
	}
}

func TestRetentionSweep_ReportsRemoveFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permission semantics differ")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	dir := t.TempDir()
	old := time.Now().Add(-90 * 24 * time.Hour)
	p := filepath.Join(dir, "audit.log.1")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := RunAuditRetentionSweep(filepath.Join(dir, "audit.log"), 30); err == nil {
		t.Fatal("remove failure not reported")
	}
}

func TestScan_TrailingPartialLineIgnored(t *testing.T) {
	s := scOpen(t)
	s.log(t, 2)
	scAppendRaw(t, s.path, "partial-line-without-newline")
	evs, err := s.l.Scan(SinceOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2", len(evs))
	}
	rep, err := VerifyChain(s.path, s.salt, s.dek)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalLines != 3 || rep.FirstBadLine != 3 {
		t.Fatalf("partial line not flagged: %+v", rep)
	}
}
