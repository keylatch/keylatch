package brokerapi

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestAdoptedMarkerRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg", "broker-adopted.json")
	if _, ok, err := ReadAdopted(path); ok || err != nil {
		t.Fatalf("missing marker = %v, %v", ok, err)
	}
	want := Adopted{At: time.Unix(1_800_000_000, 0).UTC(), UpstreamKey: []string{"github/token", "stripe/key"}}
	if err := WriteAdopted(path, want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := ReadAdopted(path)
	if err != nil || !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadAdopted = %+v, %v, %v", got, ok, err)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("marker mode = %v", info.Mode().Perm())
	}
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadAdopted(path); err == nil {
		t.Fatal("a corrupt marker must be reported")
	}
	if err := WriteAdopted(filepath.Join(os.DevNull, "x", "m.json"), want); err == nil {
		t.Fatal("an unwritable marker must be reported")
	}
}
