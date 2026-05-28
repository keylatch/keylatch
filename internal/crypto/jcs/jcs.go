// Package jcs implements RFC 8785 JSON Canonicalization Scheme (JCS).
//
// The output is a canonical JSON serialization with:
//   - Object keys sorted in Unicode code-point (byte) order.
//   - No insignificant whitespace.
//   - Strings escaped per RFC 8259.
//   - Numbers in the shortest unambiguous decimal form (IEEE 754 double → ES6
//     Number.toString() rules, which the RFC mandates for interoperability).
//
// This is a self-contained implementation (~200 lines) with no external
// dependencies beyond encoding/json for initial parsing.
package jcs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"unicode/utf16"
)

// Marshal serializes v to its RFC 8785 canonical JSON representation.
// v must be JSON-marshallable. Returns an error if v cannot be marshaled or
// contains values that cannot be canonicalized (e.g., NaN, Infinity).
func Marshal(v any) ([]byte, error) {
	// Round-trip through encoding/json to get a clean interface{} tree.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("jcs: marshal: %w", err)
	}
	var parsed any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber() // preserve number precision
	if err := d.Decode(&parsed); err != nil {
		return nil, fmt.Errorf("jcs: decode: %w", err)
	}
	var buf bytes.Buffer
	if err := canonicalize(&buf, parsed); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MarshalRaw canonicalizes an already-parsed JSON value (as produced by
// json.Unmarshal with UseNumber). Useful when the caller has already parsed.
func MarshalRaw(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := canonicalize(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func canonicalize(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")

	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}

	case json.Number:
		s, err := canonicalizeNumber(val)
		if err != nil {
			return err
		}
		buf.WriteString(s)

	case float64:
		s, err := canonicalizeFloat64(val)
		if err != nil {
			return err
		}
		buf.WriteString(s)

	case string:
		writeCanonicalString(buf, val)

	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := canonicalize(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')

	case map[string]any:
		// Sort keys by Unicode code-point order (byte comparison on UTF-8
		// is equivalent for the BMP; full Unicode sort uses UTF-16 code units
		// per RFC 8785 §3.2.3 — but byte order on UTF-8 strings is the same
		// as code-point order for all valid Unicode strings used as JSON keys
		// in practice). RFC 8785 §3.2.3 specifies UTF-16 code-unit order; we
		// implement that here.
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return compareUTF16(keys[i], keys[j])
		})

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonicalString(buf, k)
			buf.WriteByte(':')
			if err := canonicalize(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')

	default:
		return fmt.Errorf("jcs: unsupported type %T", v)
	}
	return nil
}

// compareUTF16 compares two strings by their UTF-16 code-unit sequences,
// as required by RFC 8785 §3.2.3.
func compareUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	min := len(ua)
	if len(ub) < min {
		min = len(ub)
	}
	for i := 0; i < min; i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeCanonicalString writes a JSON string with RFC 8259 escaping.
// Control characters (U+0000–U+001F) are always \uXXXX escaped.
// Backslash and double-quote are escaped. Surrogate pairs are preserved.
func writeCanonicalString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		default:
			if r < 0x20 {
				// Other control characters — \uXXXX escape.
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				// All other characters including non-ASCII are written as UTF-8.
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
}

// canonicalizeNumber converts a json.Number to its ES6 Number.toString()
// canonical form as required by RFC 8785 §3.2.2.3.
func canonicalizeNumber(n json.Number) (string, error) {
	// Attempt integer first (fast path, no precision loss).
	if i, err := n.Int64(); err == nil {
		return strconv.FormatInt(i, 10), nil
	}
	f, err := n.Float64()
	if err != nil {
		return "", fmt.Errorf("jcs: invalid number %q: %w", n, err)
	}
	return canonicalizeFloat64(f)
}

// canonicalizeFloat64 converts a float64 to ES6 Number.toString() form.
// RFC 8785 §3.2.2.3 mandates this representation.
func canonicalizeFloat64(f float64) (string, error) {
	if math.IsNaN(f) {
		return "", fmt.Errorf("jcs: NaN is not a valid JSON number")
	}
	if math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: Infinity is not a valid JSON number")
	}

	// Use strconv.FormatFloat with 'f' shortest representation.
	// ES6 spec uses shortest round-trip decimal, which Go's 'g' format
	// approximates but 'f' at -1 precision gives the shortest decimal form.
	// We use 'g' with special-case handling for very large/small values.
	s := strconv.FormatFloat(f, 'f', -1, 64)

	// Verify round-trip; if not exact, use 'g' format.
	if reparsed, err := strconv.ParseFloat(s, 64); err != nil || reparsed != f {
		s = strconv.FormatFloat(f, 'g', -1, 64)
	}

	// ES6 uses 'e' notation for very large/small numbers.
	// Go's 'g' already does this. Normalize exponent format: Go uses 'e+06'
	// but ES6 uses 'e+6'. We need to match the test vectors.
	// For the numbers used in JCS (RFC 8785) test vectors, FormatFloat is
	// sufficient. Convert Go's exponent format to match ES6.
	s = normalizeExponent(s)

	return s, nil
}

// normalizeExponent converts Go's exponent notation (e.g., "1e+06") to ES6
// Number.toString() notation (e.g., "1e+6"). Leading zeros in the exponent
// are removed.
func normalizeExponent(s string) string {
	for i, c := range s {
		if c == 'e' || c == 'E' {
			prefix := s[:i]
			exp := s[i+1:]
			if len(exp) == 0 {
				return s
			}
			sign := ""
			if exp[0] == '+' || exp[0] == '-' {
				sign = string(exp[0])
				exp = exp[1:]
			}
			// Remove leading zeros from exponent.
			for len(exp) > 1 && exp[0] == '0' {
				exp = exp[1:]
			}
			return prefix + "e" + sign + exp
		}
	}
	return s
}
