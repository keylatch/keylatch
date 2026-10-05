package audit

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

var errOpenRefused = errors.New("open refused")

// failOpens makes the logger's next n file opens fail.
func failOpens(l *Logger, n *int) {
	l.openFile = func(path string) (*os.File, error) {
		if *n > 0 {
			*n--
			return nil, errOpenRefused
		}
		return openLogFile(path)
	}
}

func TestRotationKeepsCurrentFileWhenNewFileCannotOpen(t *testing.T) {
	l, path, salt := openSmallLog(t, 1<<20, 3)
	ctx := context.Background()
	if err := l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	fails := 1
	failOpens(l, &fails)

	if err := l.Rotate(); err == nil || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Rotate = %v, want a rotation error that keeps the log writable", err)
	}
	if err := l.Ready(); err != nil {
		t.Fatalf("Ready after failed rotation = %v", err)
	}
	if err := l.Log(ctx, Event{Action: ActionWrite, Outcome: OutcomeOK}); err != nil {
		t.Fatalf("Log after failed rotation: %v", err)
	}
	if _, err := os.Stat(rotatedName(path, 1)); !os.IsNotExist(err) {
		t.Fatalf("rotated file left behind: %v", err)
	}
	if report, err := VerifyChain(path, salt, nil); err != nil || report.FirstBadLine != 0 {
		t.Fatalf("chain after failed rotation: err=%v report=%+v", err, report)
	}

	if err := l.Rotate(); err != nil {
		t.Fatalf("retried Rotate: %v", err)
	}
	if _, err := os.Stat(rotatedName(path, 1)); err != nil {
		t.Fatalf("retried rotation produced no generation: %v", err)
	}
}

func TestAutoRotationFailureRetriesLater(t *testing.T) {
	l, path, _ := openSmallLog(t, 1, 3)
	ctx := context.Background()
	fails := 1
	failOpens(l, &fails)

	if err := l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
		t.Fatalf("Log with a failing rotation: %v", err)
	}
	if l.nextRotate.IsZero() {
		t.Fatal("failed rotation was not recorded for retry")
	}
	if _, err := os.Stat(rotatedName(path, 1)); !os.IsNotExist(err) {
		t.Fatalf("rotation happened despite the failure: %v", err)
	}

	l.nextRotate = time.Now().Add(-time.Second)
	if err := l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(rotatedName(path, 1)); err != nil {
		t.Fatalf("rotation not retried: %v", err)
	}
}

func TestLogUnavailableUntilFileCanBeOpened(t *testing.T) {
	l, path, salt := openSmallLog(t, 1<<20, 3)
	ctx := context.Background()
	if err := l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK}); err != nil {
		t.Fatal(err)
	}
	// Rotation can open neither the new file nor the current one, and the
	// next two attempts to reopen fail as well.
	fails := 4
	failOpens(l, &fails)
	if err := l.Rotate(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Rotate = %v, want ErrUnavailable", err)
	}
	if err := l.Ready(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Ready = %v, want ErrUnavailable", err)
	}
	if err := l.Log(ctx, Event{Action: ActionRead, Outcome: OutcomeOK}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Log while unavailable = %v, want ErrUnavailable", err)
	}

	if err := l.Ready(); err != nil {
		t.Fatalf("Ready once the file opens again = %v", err)
	}
	if err := l.Log(ctx, Event{Action: ActionWrite, Outcome: OutcomeOK}); err != nil {
		t.Fatalf("Log after recovery: %v", err)
	}
	if report, err := VerifyChain(path, salt, nil); err != nil || report.FirstBadLine != 0 {
		t.Fatalf("chain after recovery: err=%v report=%+v", err, report)
	}
}
