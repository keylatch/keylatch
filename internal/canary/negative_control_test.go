package canary_test

import (
	"testing"

	"github.com/keylatch/keylatch/internal/canary"
)

// SC6-8 negative-control test: verifies canary suite catches a deliberately introduced leak.
func TestNegativeControlLeakDetected(t *testing.T) {
	// Seed a buffer that deliberately contains the core sentinel, simulating
	// what a production code path would expose in stdout.
	poisoned := []byte("stdout output: " + canary.CoreSentinel + " end")

	spy := &spyTB{}
	canary.AssertNoLeak(spy,
		[]string{canary.CoreSentinel},
		canary.Stdout(poisoned),
	)

	if len(spy.errors) == 0 {
		t.Error("SC6-8: AssertNoLeak did not call Errorf for a deliberately introduced leak")
	}
}
