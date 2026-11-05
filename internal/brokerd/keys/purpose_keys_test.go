package keys

import (
	"bytes"
	"testing"
)

// The sync and service keys are stable per partition, differ between
// partitions and from each other and from the token key.
func TestPurposeKeysAreIndependent(t *testing.T) {
	h := openTest(t, t.TempDir(), testRoot(3))
	syncA, err := h.SyncKeyFor("1000")
	if err != nil {
		t.Fatal(err)
	}
	syncB, _ := h.SyncKeyFor("1001")
	svcA, err := h.ServiceKeyFor("1000")
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := h.TokenKeyFor("1000")
	all := map[string][]byte{"sync A": syncA, "sync B": syncB, "service A": svcA, "token A": tok}
	for n1, k1 := range all {
		if len(k1) != 32 {
			t.Fatalf("%s has length %d", n1, len(k1))
		}
		for n2, k2 := range all {
			if n1 != n2 && bytes.Equal(k1, k2) {
				t.Fatalf("%s equals %s", n1, n2)
			}
		}
	}
	if again, _ := h.SyncKeyFor("1000"); !bytes.Equal(again, syncA) {
		t.Fatal("the sync key must be stable")
	}
	if again, _ := h.ServiceKeyFor("1000"); !bytes.Equal(again, svcA) {
		t.Fatal("the service key must be stable")
	}
}
