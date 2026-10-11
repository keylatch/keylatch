package jcs

import "testing"

func TestNormalizeExponent(t *testing.T) {
	cases := map[string]string{
		"1e+06":   "1e+6",
		"1E+06":   "1e+6",
		"2.5e-07": "2.5e-7",
		"1e+00":   "1e+0",
		"1e100":   "1e100",
		"3e":      "3e",
		"1e+":     "1e+",
		"42":      "42",
		"0.001":   "0.001",
	}
	for in, want := range cases {
		if got := normalizeExponent(in); got != want {
			t.Errorf("normalizeExponent(%q) = %q, want %q", in, got, want)
		}
	}
}
