package cli

import (
	"errors"
	"testing"
)

func TestIsCobraGeneratedError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unknown command", errors.New(`unknown command "foo" for "keylatch"`), true},
		{"invalid argument", errors.New(`invalid argument "x" for "keylatch list"`), true},
		{"requires at least", errors.New("requires at least 1 arg(s), only received 0"), true},
		{"accepts at most", errors.New("accepts at most 1 arg(s), received 2"), true},
		{"accepts between", errors.New("accepts between 1 and 2 arg(s), received 3"), true},
		{"accepts exact", errors.New("accepts 1 arg(s), received 0"), true},
		{"unknown flag", errors.New("unknown flag: --bogus"), true},
		{"unknown shorthand flag", errors.New(`unknown shorthand flag: 'x' in -xk`), true},
		{"flag needs an argument", errors.New("flag needs an argument: --int"), true},
		{"application error", errors.New("keychain Init: create-keychain failed (exit 1)"), false},
		{"CLIError", &CLIError{Class: "UsageError", Code: 1, Message: "bad input"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsCobraGeneratedError(tc.err)
			if got != tc.want {
				t.Errorf("IsCobraGeneratedError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
