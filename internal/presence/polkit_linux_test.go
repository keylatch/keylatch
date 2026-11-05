//go:build linux

package presence

import "testing"

func TestParseStartTime(t *testing.T) {
	// comm holds spaces and a parenthesis; field 22 is the start time.
	stat := "1234 (a b) c) S 1 1234 1234 34816 1234 4194304 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615"
	got, err := parseStartTime(stat)
	if err != nil || got != "987654" {
		t.Fatalf("parseStartTime = %q, %v", got, err)
	}
	if _, err := parseStartTime("no parenthesis"); err == nil {
		t.Fatal("malformed stat accepted")
	}
	if _, err := parseStartTime("1 (x) S 1"); err == nil {
		t.Fatal("short stat accepted")
	}
}
