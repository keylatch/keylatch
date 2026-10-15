package redactor

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestScanChangedFindsNewAndRewrittenFiles(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "old.txt"), "unchanged "+string(testSecret))
	write(t, filepath.Join(dir, "same-size.txt"), "aaaaaaaaaaaa")
	before, err := TakeSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(testSecret)

	write(t, filepath.Join(dir, "sub", "raw.txt"), "k="+string(testSecret))
	write(t, filepath.Join(dir, "b64.txt"), base64.StdEncoding.EncodeToString([]byte("x:"+string(testSecret))))
	write(t, filepath.Join(dir, "hex.txt"), hex.EncodeToString(testSecret))
	write(t, filepath.Join(dir, "clean.txt"), "nothing")
	write(t, filepath.Join(dir, "same-size.txt"), "bbbbbbbbbbbb")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "same-size.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, hex.EncodeToString(testSecret)), "innocuous")

	got, err := m.ScanChanged(before, ScanReport)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]Finding{}
	for _, f := range got {
		paths[filepath.Base(f.Path)] = f
	}
	for _, name := range []string{"raw.txt", "b64.txt", "hex.txt", hex.EncodeToString(testSecret)} {
		if _, ok := paths[name]; !ok {
			t.Fatalf("missing finding for %s: %+v", name, got)
		}
	}
	if !paths[hex.EncodeToString(testSecret)].Name {
		t.Fatal("name finding not flagged")
	}
	if _, ok := paths["old.txt"]; ok {
		t.Fatal("unchanged file reported")
	}
	if _, ok := paths["clean.txt"]; ok {
		t.Fatal("clean file reported")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sub", "raw.txt")); string(b) != "k="+string(testSecret) {
		t.Fatal("report mode modified the file")
	}
}

func TestScanChangedRedactsInPlace(t *testing.T) {
	dir := t.TempDir()
	before, _ := TakeSnapshot(dir)
	p := filepath.Join(dir, "out.log")
	write(t, p, "token "+string(testSecret)+" end")
	got, err := NewMatcher(testSecret).ScanChanged(before, ScanRedact)
	if err != nil || len(got) != 1 || !got[0].Redacted {
		t.Fatalf("got %+v err %v", got, err)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "token "+Marker+" end" {
		t.Fatalf("content %q", b)
	}
	if info, _ := os.Stat(p); info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatal("temp file left behind")
	}
}

func TestScanChangedSkipsSymlinksAndEmptyMatcher(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	write(t, outside, string(testSecret))
	before, _ := TakeSnapshot(dir)
	if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable")
	}
	got, err := NewMatcher(testSecret).ScanChanged(before, ScanRedact)
	if err != nil || len(got) != 0 {
		t.Fatalf("symlink followed: %+v %v", got, err)
	}
	if got, _ := NewMatcher().ScanChanged(before, ScanReport); got != nil {
		t.Fatal("empty matcher produced findings")
	}
}

func TestScanSnapshotMissingRoot(t *testing.T) {
	if _, err := TakeSnapshot(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatal(err)
	}
}
