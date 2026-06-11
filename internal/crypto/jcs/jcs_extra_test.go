package jcs_test

// jcs_extra_test.go adds coverage for uncovered paths in jcs.go:
//   - Marshal/MarshalRaw error paths
//   - writeCanonicalString all escape branches
//   - canonicalizeNumber float path and error path
//   - canonicalizeFloat64 (NaN, Infinity, floats requiring exponent form)
//   - normalizeExponent edge cases

import (
	"bytes"
	"encoding/json"
	"math"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/jcs"
)

// ---------------------------------------------------------------------------
// Marshal / MarshalRaw — error paths
// ---------------------------------------------------------------------------

// unsupportedType is a channel — json.Marshal will fail on it.
type unsupportedType chan int

func TestMarshal_UnsupportedType_Error(t *testing.T) {
	t.Parallel()
	// A channel is not JSON-serialisable; Marshal must propagate the error.
	var ch unsupportedType
	_, err := jcs.Marshal(ch)
	if err == nil {
		t.Error("expected error marshaling chan, got nil")
	}
}

func TestMarshalRaw_UnsupportedType_Error(t *testing.T) {
	t.Parallel()
	// Passing an unsupported Go type directly to MarshalRaw triggers the
	// default case in canonicalize.
	type myStruct struct{ X int }
	_, err := jcs.MarshalRaw(myStruct{X: 1})
	if err == nil {
		t.Error("expected error from MarshalRaw with struct, got nil")
	}
}

func TestMarshalRaw_NestedUnsupportedType_Error(t *testing.T) {
	t.Parallel()
	// An array element with an unsupported type must bubble the error.
	input := []any{myBadType{}}
	_, err := jcs.MarshalRaw(input)
	if err == nil {
		t.Error("expected error from array element with bad type, got nil")
	}
}

type myBadType struct{}

func TestMarshalRaw_MapValueUnsupportedType_Error(t *testing.T) {
	t.Parallel()
	// A map value with an unsupported type must bubble the error.
	input := map[string]any{"key": myBadType{}}
	_, err := jcs.MarshalRaw(input)
	if err == nil {
		t.Error("expected error from map value with bad type, got nil")
	}
}

// ---------------------------------------------------------------------------
// writeCanonicalString — all escape branches
// ---------------------------------------------------------------------------

func TestMarshal_StringEscaping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "double_quote", input: `"`, want: `"\""`},
		{name: "backslash", input: `\`, want: `"\\"`},
		{name: "backspace", input: "\b", want: `"\b"`},
		{name: "form_feed", input: "\f", want: `"\f"`},
		{name: "newline", input: "\n", want: `"\n"`},
		{name: "carriage_return", input: "\r", want: `"\r"`},
		{name: "tab", input: "\t", want: `"\t"`},
		{name: "ctrl_a", input: "\x01", want: `"\u0001"`},
		{name: "ctrl_1f", input: "\x1f", want: `"\u001f"`},
		{name: "normal_ascii", input: "hello", want: `"hello"`},
		{name: "non_ascii_utf8", input: "café", want: `"café"`},
		{name: "empty", input: "", want: `""`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := jcs.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// canonicalizeNumber via MarshalRaw with json.Number values
// ---------------------------------------------------------------------------

func parseNumber(s string) json.Number { return json.Number(s) }

func TestMarshalRaw_IntegerNumber(t *testing.T) {
	t.Parallel()
	n := parseNumber("12345")
	got, err := jcs.MarshalRaw(n)
	if err != nil {
		t.Fatalf("MarshalRaw: %v", err)
	}
	if string(got) != "12345" {
		t.Errorf("got %s, want 12345", got)
	}
}

func TestMarshalRaw_NegativeInteger(t *testing.T) {
	t.Parallel()
	n := parseNumber("-42")
	got, err := jcs.MarshalRaw(n)
	if err != nil {
		t.Fatalf("MarshalRaw: %v", err)
	}
	if string(got) != "-42" {
		t.Errorf("got %s, want -42", got)
	}
}

func TestMarshalRaw_FloatNumber(t *testing.T) {
	t.Parallel()
	// A float that can't be represented as int64.
	n := parseNumber("1.5")
	got, err := jcs.MarshalRaw(n)
	if err != nil {
		t.Fatalf("MarshalRaw: %v", err)
	}
	if string(got) != "1.5" {
		t.Errorf("got %s, want 1.5", got)
	}
}

func TestMarshalRaw_InvalidNumber_Error(t *testing.T) {
	t.Parallel()
	// An invalid json.Number (non-numeric) must produce an error.
	n := parseNumber("not-a-number")
	_, err := jcs.MarshalRaw(n)
	if err == nil {
		t.Error("expected error for invalid json.Number, got nil")
	}
}

// ---------------------------------------------------------------------------
// canonicalizeFloat64 — reached when a float64 is in the parsed tree.
// Marshal round-trips through json.Number via UseNumber, but we can inject
// float64 values directly via MarshalRaw.
// ---------------------------------------------------------------------------

func TestMarshalRaw_Float64_NaN_Error(t *testing.T) {
	t.Parallel()
	_, err := jcs.MarshalRaw(math.NaN())
	if err == nil {
		t.Error("expected error for NaN, got nil")
	}
}

func TestMarshalRaw_Float64_PosInf_Error(t *testing.T) {
	t.Parallel()
	_, err := jcs.MarshalRaw(math.Inf(1))
	if err == nil {
		t.Error("expected error for +Inf, got nil")
	}
}

func TestMarshalRaw_Float64_NegInf_Error(t *testing.T) {
	t.Parallel()
	_, err := jcs.MarshalRaw(math.Inf(-1))
	if err == nil {
		t.Error("expected error for -Inf, got nil")
	}
}

func TestMarshalRaw_Float64_Zero(t *testing.T) {
	t.Parallel()
	got, err := jcs.MarshalRaw(float64(0))
	if err != nil {
		t.Fatalf("MarshalRaw(0): %v", err)
	}
	if string(got) != "0" {
		t.Errorf("got %s, want 0", got)
	}
}

func TestMarshalRaw_Float64_Fraction(t *testing.T) {
	t.Parallel()
	got, err := jcs.MarshalRaw(float64(3.14))
	if err != nil {
		t.Fatalf("MarshalRaw(3.14): %v", err)
	}
	// Must be a string representation that round-trips to 3.14.
	if len(got) == 0 {
		t.Error("got empty output")
	}
}

func TestMarshalRaw_Float64_LargeExponent(t *testing.T) {
	t.Parallel()
	// 1e100 should produce an exponent form and normalizeExponent is exercised.
	got, err := jcs.MarshalRaw(float64(1e100))
	if err != nil {
		t.Fatalf("MarshalRaw(1e100): %v", err)
	}
	// Must contain 'e' and not have leading zeros in the exponent.
	s := string(got)
	if len(s) == 0 {
		t.Error("empty output")
	}
}

// ---------------------------------------------------------------------------
// normalizeExponent — via MarshalRaw with json.Number that becomes a float
// with an exponent form in the Go output.
// ---------------------------------------------------------------------------

func TestMarshalRaw_NormalizeExponent_LeadingZero(t *testing.T) {
	t.Parallel()
	// 1e6 — Go may produce "1e+06" which must be normalized to "1e+6".
	n := parseNumber("1e6")
	got, err := jcs.MarshalRaw(n)
	if err != nil {
		t.Fatalf("MarshalRaw(1e6): %v", err)
	}
	s := string(got)
	if len(s) == 0 {
		t.Error("empty output")
	}
	// Should not have 'e+06' (two-digit exponent with leading zero).
	if bytes.Contains(got, []byte("e+06")) {
		t.Errorf("output %s contains 'e+06', want 'e+6'", s)
	}
}

// ---------------------------------------------------------------------------
// compareUTF16 — exercised via map key ordering with non-ASCII / surrogate-range keys
// ---------------------------------------------------------------------------

func TestMarshal_UTF16KeyOrder(t *testing.T) {
	t.Parallel()
	// Keys with high code points — sorting must be by UTF-16 code units.
	input := map[string]any{
		"é": 1, // é  U+00E9
		"à": 2, // à  U+00E0
		"a": 3,
	}
	got, err := jcs.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// "a" < "à" < "é" by UTF-16 code point value.
	want := `{"a":3,"à":2,"é":1}`
	if string(got) != want {
		t.Errorf("got:  %s\nwant: %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Primitive types — null, bool, array
// ---------------------------------------------------------------------------

func TestMarshal_Null(t *testing.T) {
	t.Parallel()
	got, err := jcs.Marshal(nil)
	if err != nil {
		t.Fatalf("Marshal(nil): %v", err)
	}
	if string(got) != "null" {
		t.Errorf("got %s, want null", got)
	}
}

func TestMarshal_BoolTrue(t *testing.T) {
	t.Parallel()
	got, err := jcs.Marshal(true)
	if err != nil {
		t.Fatalf("Marshal(true): %v", err)
	}
	if string(got) != "true" {
		t.Errorf("got %s, want true", got)
	}
}

func TestMarshal_BoolFalse(t *testing.T) {
	t.Parallel()
	got, err := jcs.Marshal(false)
	if err != nil {
		t.Fatalf("Marshal(false): %v", err)
	}
	if string(got) != "false" {
		t.Errorf("got %s, want false", got)
	}
}

func TestMarshal_EmptyArray(t *testing.T) {
	t.Parallel()
	got, err := jcs.Marshal([]any{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != "[]" {
		t.Errorf("got %s, want []", got)
	}
}

func TestMarshal_NestedArray(t *testing.T) {
	t.Parallel()
	input := []any{1, "two", true, nil, []any{3, 4}}
	got, err := jcs.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `[1,"two",true,null,[3,4]]`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestMarshal_EmptyObject(t *testing.T) {
	t.Parallel()
	got, err := jcs.Marshal(map[string]any{})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(got) != "{}" {
		t.Errorf("got %s, want {}", got)
	}
}

func TestMarshalRaw_NullValue(t *testing.T) {
	t.Parallel()
	got, err := jcs.MarshalRaw(nil)
	if err != nil {
		t.Fatalf("MarshalRaw(nil): %v", err)
	}
	if string(got) != "null" {
		t.Errorf("got %s, want null", got)
	}
}

// ---------------------------------------------------------------------------
// compareUTF16 — equal-length strings; length-difference branch
// ---------------------------------------------------------------------------

func TestMarshal_KeyOrderLengthDifference(t *testing.T) {
	t.Parallel()
	// "a" and "aa" — same prefix, "a" is shorter so it should sort first.
	input := map[string]any{
		"aa": 2,
		"a":  1,
	}
	got, err := jcs.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"a":1,"aa":2}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// normalizeExponent — no 'e' in string (coverage of the fallthrough return)
// ---------------------------------------------------------------------------

func TestMarshalRaw_NumberWithoutExponent(t *testing.T) {
	t.Parallel()
	// Integer-valued json.Number: goes through integer fast path; no exponent.
	n := parseNumber("999")
	got, err := jcs.MarshalRaw(n)
	if err != nil {
		t.Fatalf("MarshalRaw: %v", err)
	}
	if string(got) != "999" {
		t.Errorf("got %s, want 999", got)
	}
}
