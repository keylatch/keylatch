package cmderr_test

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/keylatch/keylatch/internal/cmderr"
)

// ---- Wrap tests ----

func TestWrap_SetsAllFields(t *testing.T) {
	cause := errors.New("underlying error")
	e := cmderr.Wrap("summary text", cause, "do the thing", "my-code")

	if e.Summary != "summary text" {
		t.Errorf("Summary: got %q, want %q", e.Summary, "summary text")
	}
	if e.Cause != cause {
		t.Errorf("Cause: got %v, want %v", e.Cause, cause)
	}
	if e.Hint != "do the thing" {
		t.Errorf("Hint: got %q, want %q", e.Hint, "do the thing")
	}
	if e.Code != "my-code" {
		t.Errorf("Code: got %q, want %q", e.Code, "my-code")
	}
}

func TestWrap_NilCause(t *testing.T) {
	e := cmderr.Wrap("no cause", nil, "", "")
	if e.Cause != nil {
		t.Errorf("expected nil Cause, got %v", e.Cause)
	}
}

// ---- Error() tests ----

func TestE_Error_ReturnsSummaryOnly(t *testing.T) {
	e := cmderr.Wrap("just the summary", errors.New("hidden cause"), "hint", "code")
	if e.Error() != "just the summary" {
		t.Errorf("Error(): got %q, want %q", e.Error(), "just the summary")
	}
}

// ---- Unwrap tests ----

func TestE_Unwrap_ReturnsCause(t *testing.T) {
	cause := errors.New("root cause")
	e := cmderr.Wrap("summary", cause, "", "")
	if e.Unwrap() != cause {
		t.Errorf("Unwrap(): got %v, want %v", e.Unwrap(), cause)
	}
}

func TestE_Unwrap_NilCause(t *testing.T) {
	e := cmderr.Wrap("summary", nil, "", "")
	if e.Unwrap() != nil {
		t.Errorf("Unwrap() with nil cause: got %v, want nil", e.Unwrap())
	}
}

func TestE_ErrorsIs_WorksThroughUnwrap(t *testing.T) {
	sentinel := errors.New("sentinel")
	e := cmderr.Wrap("wrapper", sentinel, "", "")
	if !errors.Is(e, sentinel) {
		t.Error("errors.Is should find sentinel through Unwrap chain")
	}
}

// ---- Format tests ----

func TestFormat_FullOutput(t *testing.T) {
	cause := errors.New("disk is full")
	e := cmderr.Wrap("could not write file", cause, "free up disk space", "write-fail")

	var buf bytes.Buffer
	cmderr.Format(&buf, e)
	got := buf.String()

	want := "Error: could not write file\n Cause: disk is full\n Fix: free up disk space\n Docs: keylatch.dev/errors/write-fail\n"
	if got != want {
		t.Errorf("Format() full output:\ngot: %q\nwant: %q", got, want)
	}
}

func TestFormat_NoCause(t *testing.T) {
	e := cmderr.Wrap("something failed", nil, "try again", "retry")

	var buf bytes.Buffer
	cmderr.Format(&buf, e)
	got := buf.String()

	want := "Error: something failed\n Fix: try again\n Docs: keylatch.dev/errors/retry\n"
	if got != want {
		t.Errorf("Format() no-cause output:\ngot: %q\nwant: %q", got, want)
	}
}

func TestFormat_NoHint(t *testing.T) {
	cause := fmt.Errorf("network timeout")
	e := cmderr.Wrap("connection failed", cause, "", "conn-fail")

	var buf bytes.Buffer
	cmderr.Format(&buf, e)
	got := buf.String()

	want := "Error: connection failed\n Cause: network timeout\n Docs: keylatch.dev/errors/conn-fail\n"
	if got != want {
		t.Errorf("Format() no-hint output:\ngot: %q\nwant: %q", got, want)
	}
}

func TestFormat_NoCode(t *testing.T) {
	cause := errors.New("permission denied")
	e := cmderr.Wrap("access denied", cause, "check permissions", "")

	var buf bytes.Buffer
	cmderr.Format(&buf, e)
	got := buf.String()

	want := "Error: access denied\n Cause: permission denied\n Fix: check permissions\n"
	if got != want {
		t.Errorf("Format() no-code output:\ngot: %q\nwant: %q", got, want)
	}
}

func TestFormat_SummaryOnly(t *testing.T) {
	e := cmderr.Wrap("bare error", nil, "", "")

	var buf bytes.Buffer
	cmderr.Format(&buf, e)
	got := buf.String()

	want := "Error: bare error\n"
	if got != want {
		t.Errorf("Format() summary-only output:\ngot: %q\nwant: %q", got, want)
	}
}

// ---- Distance tests ----

func TestDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"a", "", 1},
		{"", "a", 1},
		{"abc", "abc", 0},
		{"kitten", "sitting", 3},
		{"openai", "opanai", 1},
		{"openai", "openai", 0},
		{"anthropic", "antrpic", 2},
		{"abc", "xyz", 3},
	}
	for _, tc := range cases {
		got := cmderr.Distance(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("Distance(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// ---- SuggestProvider tests ----

func TestSuggestProvider(t *testing.T) {
	slugs := []string{"openai", "anthropic", "google-ai", "openrouter", "mistral"}

	cases := []struct {
		input     string
		threshold int
		want      string
	}{
		{"openai", 2, ""},           // exact match → no suggestion
		{"opanai", 2, "openai"},     // distance 1
		{"antrpic", 2, "anthropic"}, // distance 2
		{"totally-wrong", 2, ""},    // too far
		{"mistral", 2, ""},          // exact
		{"mistra", 2, "mistral"},    // distance 1
	}
	for _, tc := range cases {
		got := cmderr.SuggestProvider(tc.input, slugs, tc.threshold)
		if got != tc.want {
			t.Errorf("SuggestProvider(%q, slugs, %d) = %q, want %q", tc.input, tc.threshold, got, tc.want)
		}
	}
}
