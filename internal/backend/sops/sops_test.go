package sops

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/backend"
	vmeta "github.com/keylatch/keylatch/internal/vault/meta"
)

func want(t *testing.T, v *Values, path, value string) {
	t.Helper()
	got, ok := v.Lookup(path)
	if !ok || string(got) != value {
		t.Fatalf("Lookup(%q) = %q, %v; want %q", path, got, ok, value)
	}
}

func TestDecryptEachFormat(t *testing.T) {
	key := newKey(t)
	for _, f := range []Format{FormatJSON, FormatYAML} {
		t.Run(string(f), func(t *testing.T) {
			v, err := Decrypt(f, buildDoc(t, f, key, sampleDoc, docOptions{}), key.ids(t), DecryptOptions{})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Clear()
			want(t, v, "db/password", "hunter2")
			want(t, v, "db/port", "5432")
			want(t, v, "db/ssl", "true")
			want(t, v, "db/ratio", "1.5")
			want(t, v, "hosts/0", "a.example")
			want(t, v, "hosts/1", "b.example")
			want(t, v, "stripe_key", "sk_live_example")
			want(t, v, "note_unencrypted", "public")
			for _, missing := range []string{"db", "hosts/2", "hosts/x", "nope", "db/password/deeper", ""} {
				if got, ok := v.Lookup(missing); ok {
					t.Errorf("Lookup(%q) found %q", missing, got)
				}
			}
		})
	}
	t.Run("dotenv", func(t *testing.T) {
		doc := []kv{{"API_KEY", "one"}, {"DB_URL", "postgres://x"}}
		v, err := Decrypt(FormatDotenv, buildDoc(t, FormatDotenv, key, doc, docOptions{}), key.ids(t), DecryptOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer v.Clear()
		want(t, v, "API_KEY", "one")
		want(t, v, "DB_URL", "postgres://x")
	})
}

func TestArmoredAndBinaryAgeFiles(t *testing.T) {
	key := newKey(t)
	for _, armor := range []bool{true, false} {
		for _, size := range []int{0, 1, ageChunk - 1, ageChunk, ageChunk + 1, 3*ageChunk + 17} {
			plain := bytes.Repeat([]byte{0x5a}, size)
			got, err := decryptAge(ageEncrypt(t, key.public, plain, armor), key.ids(t))
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("armor=%v size=%d: %v", armor, size, err)
			}
		}
	}
}

func TestAgeRefusals(t *testing.T) {
	key, other := newKey(t), newKey(t)
	file := ageEncrypt(t, key.public, []byte("payload"), false)
	if _, err := decryptAge(file, other.ids(t)); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("wrong identity = %v", err)
	}
	flip := func(i int) []byte {
		c := slices.Clone(file)
		c[i] ^= 1
		return c
	}
	hdrEnd := bytes.Index(file, []byte("---")) + 6
	for name, f := range map[string][]byte{
		"tampered header":    flip(bytes.Index(file, []byte("-> X25519 ")) + 14),
		"tampered mac":       flip(hdrEnd),
		"tampered payload":   flip(len(file) - 1),
		"truncated payload":  file[:len(file)-3],
		"no payload":         file[:bytes.LastIndex(file, []byte("---"))+len("--- ")+43+1],
		"not age":            []byte("hello"),
		"unknown stanza":     bytes.Replace(file, []byte("-> X25519 "), []byte("-> scrypt "), 1),
		"armor not base64":   []byte("-----BEGIN AGE ENCRYPTED FILE-----\n!!!\n-----END AGE ENCRYPTED FILE-----\n"),
		"stanza before head": []byte(ageVersionLine + "\nbody\n"),
	} {
		if _, err := decryptAge(f, key.ids(t)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A chunk dropped from a multi-chunk file is caught by the final-chunk flag.
	multi := ageEncrypt(t, key.public, bytes.Repeat([]byte{1}, 2*ageChunk+5), false)
	if _, err := decryptAge(multi[:len(multi)-(ageChunk+16)], key.ids(t)); err == nil {
		t.Error("a truncated stream was accepted")
	}
}

func TestParseIdentities(t *testing.T) {
	key := newKey(t)
	if _, err := ParseIdentities(strings.NewReader(key.identity)); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]string{
		"empty":        "# only a comment\n",
		"not a key":    "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n",
		"bad checksum": key.identity[:len(key.identity)-1] + "Q\n",
		"short":        strings.ToUpper(bech32Encode(ageSecretHRP, []byte{1, 2, 3})) + "\n",
		"mixed case":   key.identity[:20] + strings.ToLower(key.identity[20:]) + "\n",
	} {
		if _, err := ParseIdentities(strings.NewReader(in)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestBech32(t *testing.T) {
	data := []byte("keylatch-bech32-roundtrip-0123456789")
	hrp, five, err := bech32Decode(bech32Encode("test", data))
	if err != nil || hrp != "test" {
		t.Fatalf("decode = %q, %v", hrp, err)
	}
	if back, err := convertBits(five, 5, 8); err != nil || !bytes.Equal(back, data) {
		t.Fatalf("convert = %q, %v", back, err)
	}
	for _, bad := range []string{"", "nodivider", "x1", "test1qqqqqqq!", "test1qqqqqqq"} {
		if _, _, err := bech32Decode(bad); err == nil {
			t.Errorf("%q decoded", bad)
		}
	}
	if _, err := convertBits([]byte{40}, 5, 8); err == nil {
		t.Error("an out-of-range group converted")
	}
	if _, err := convertBits([]byte{1, 1}, 5, 8); err == nil {
		t.Error("non-zero padding converted")
	}
}

func TestTamperedFilesAreCaughtByTheMAC(t *testing.T) {
	key := newKey(t)
	file := buildDoc(t, FormatYAML, key, sampleDoc, docOptions{})
	// Dropping a value leaves every remaining value authentic, but the MAC no
	// longer matches the whole.
	dropped := regexp.MustCompile(`(?m)^stripe_key: .*\n`).ReplaceAll(file, nil)
	if bytes.Equal(dropped, file) {
		t.Fatal("test setup: nothing dropped")
	}
	if _, err := Decrypt(FormatYAML, dropped, key.ids(t), DecryptOptions{}); !errors.Is(err, ErrMAC) {
		t.Fatalf("a dropped value = %v", err)
	}
	if v, err := Decrypt(FormatYAML, dropped, key.ids(t), DecryptOptions{SkipMAC: true}); err != nil {
		t.Fatalf("SkipMAC = %v", err)
	} else {
		want(t, v, "db/password", "hunter2")
	}
	// A plain value changed in a file that hashes plain values.
	edited := bytes.Replace(file, []byte("note_unencrypted: \"public\""), []byte("note_unencrypted: \"changed\""), 1)
	if _, err := Decrypt(FormatYAML, edited, key.ids(t), DecryptOptions{}); !errors.Is(err, ErrMAC) {
		t.Fatalf("an edited plain value = %v", err)
	}
	// Two values swapped between paths fail authentication (the path is the AAD).
	a := regexp.MustCompile(`(?m)^  password: (ENC.*)$`).FindSubmatch(file)
	b := regexp.MustCompile(`(?m)^stripe_key: (ENC.*)$`).FindSubmatch(file)
	swapped := bytes.Replace(bytes.Replace(file, a[1], []byte("@@A"), 1), b[1], a[1], 1)
	swapped = bytes.Replace(swapped, []byte("@@A"), b[1], 1)
	if _, err := Decrypt(FormatYAML, swapped, key.ids(t), DecryptOptions{SkipMAC: true}); err == nil {
		t.Fatal("values swapped between paths were accepted")
	}
}

func TestMacOnlyEncryptedIsRefusedUnlessSkipped(t *testing.T) {
	key := newKey(t)
	file := buildDoc(t, FormatYAML, key, sampleDoc, docOptions{macOnlyEnc: true})
	if _, err := Decrypt(FormatYAML, file, key.ids(t), DecryptOptions{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("mac_only_encrypted = %v", err)
	}
	if v, err := Decrypt(FormatYAML, file, key.ids(t), DecryptOptions{SkipMAC: true}); err != nil {
		t.Fatalf("skipped = %v", err)
	} else {
		want(t, v, "stripe_key", "sk_live_example")
	}
}

func TestDecryptRefusals(t *testing.T) {
	key, other := newKey(t), newKey(t)
	file := buildDoc(t, FormatJSON, key, sampleDoc, docOptions{})
	if _, err := Decrypt(FormatJSON, file, other.ids(t), DecryptOptions{}); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("wrong identity = %v", err)
	}
	for name, in := range map[string]struct {
		f Format
		b string
	}{
		"not json":           {FormatJSON, "{"},
		"json array":         {FormatJSON, "[1]"},
		"no sops section":    {FormatJSON, `{"a":"b"}`},
		"sops without mac":   {FormatJSON, `{"sops":{"age":[]}}`},
		"no recipient":       {FormatJSON, `{"sops":{"mac":"x","lastmodified":"y"}}`},
		"yaml alias":         {FormatYAML, "a: &x 1\nb: *x\nsops:\n  mac: x\n  lastmodified: y\n"},
		"yaml not a mapping": {FormatYAML, "- 1\n"},
		"dotenv no equals":   {FormatDotenv, "oops\n"},
		"dotenv no sops":     {FormatDotenv, "A=1\n"},
		"unknown format":     {Format("toml"), "x"},
	} {
		if _, err := Decrypt(in.f, []byte(in.b), key.ids(t), DecryptOptions{}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// A data key of the wrong length is rejected.
	s := newSopsFile(t)
	s.dataKey = s.dataKey[:16]
	bad := ageEncrypt(t, key.public, s.dataKey, true)
	doc := `{"a":"x","sops":{"age":[{"recipient":"r","enc":` + jsonString(string(bad)) + `}],"lastmodified":"t","mac":"m"}}`
	if _, err := Decrypt(FormatJSON, []byte(doc), key.ids(t), DecryptOptions{}); !errors.Is(err, ErrFormat) {
		t.Fatalf("short data key = %v", err)
	}
}

func jsonString(s string) string { return writeJSON(s) }

func TestFormatDetection(t *testing.T) {
	for name, want := range map[string]Format{"s.json": FormatJSON, "s.yaml": FormatYAML, "s.yml": FormatYAML, "prod.env": FormatDotenv, "x.dotenv": FormatDotenv, "plain": FormatYAML} {
		if got := DetectFormat(name); got != want {
			t.Errorf("DetectFormat(%q) = %s", name, got)
		}
	}
}

func TestPlainTextFormatsLikeSops(t *testing.T) {
	for in, want := range map[any]string{nil: "", "s": "s", true: "True", false: "False", 7: "7", int64(8): "8", uint64(9): "9", 1.5: "1.5", 2.0: "2", struct{}{}: "{}"} {
		if got := plainText(in); got != want {
			t.Errorf("plainText(%#v) = %q, want %q", in, got, want)
		}
	}
}

func fileBackend(t *testing.T, f Format, key testKey, doc []kv) (*Backend, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets."+string(f))
	if err := os.WriteFile(path, buildDoc(t, f, key, doc, docOptions{}), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Open(Options{File: path, AgeKey: key.identity})
	if err != nil {
		t.Fatal(err)
	}
	return b, path
}

func TestBackendGetAndList(t *testing.T) {
	key := newKey(t)
	b, _ := fileBackend(t, FormatJSON, key, sampleDoc)
	ctx := context.Background()
	v, m, err := b.Get(ctx, "db/password")
	if err != nil || string(v) != "hunter2" || m.Backend != "sops" {
		t.Fatalf("Get = %q, %+v, %v", v, m, err)
	}
	if _, _, err := b.Get(ctx, "db/missing"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	entries, err := b.List(ctx, "db/")
	if err != nil || len(entries) != 4 || entries[0].Path != "db/password" && entries[0].Path != "db/port" && entries[0].Path != "db/ratio" && entries[0].Path != "db/ssl" {
		t.Fatalf("List = %+v, %v", entries, err)
	}
	all, _ := b.List(ctx, "")
	paths := make([]string, len(all))
	for i, e := range all {
		paths[i] = e.Path
	}
	if !slices.Contains(paths, "hosts/0") || !slices.Contains(paths, "hosts/1") || !slices.Contains(paths, "stripe_key") {
		t.Fatalf("paths = %v", paths)
	}
	if b.Name() != "sops" || !strings.HasPrefix(b.ID(), "sops:") || !slices.Contains(b.Capabilities(), backend.CapList) || b.Close() != nil {
		t.Fatal("backend identity")
	}
}

func TestBackendIsReadOnly(t *testing.T) {
	key := newKey(t)
	b, path := fileBackend(t, FormatYAML, key, sampleDoc)
	before, _ := os.ReadFile(path)
	ctx := context.Background()
	for _, err := range []error{
		b.Set(ctx, "a", []byte("v"), backend.Meta{}), b.Delete(ctx, "a"), b.SetMeta(ctx, "a", vmeta.Meta{}),
		b.SetVersioned(ctx, "a", 1, nil), b.DeleteVersioned(ctx, "a", 1),
	} {
		if !errors.Is(err, backend.ErrNotSupported) {
			t.Errorf("a write returned %v", err)
		}
	}
	if _, err := b.GetMeta(ctx, "a"); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("GetMeta")
	}
	if _, err := b.ListMeta(ctx, ""); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("ListMeta")
	}
	if _, err := b.GetVersioned(ctx, "a", 1); !errors.Is(err, backend.ErrNotSupported) {
		t.Error("GetVersioned")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("the file changed")
	}
}

func TestBackendNeverWritesPlaintextToDisk(t *testing.T) {
	key := newKey(t)
	b, path := fileBackend(t, FormatYAML, key, sampleDoc)
	dir := filepath.Dir(path)
	if _, _, err := b.Get(context.Background(), "stripe_key"); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the backend left files next to the secrets: %v", entries)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("sk_live_example")) {
		t.Fatal("the file holds the plaintext")
	}
}

func TestBackendIdentityFileAndErrors(t *testing.T) {
	key := newKey(t)
	dir := t.TempDir()
	secrets := filepath.Join(dir, "s.json")
	if err := os.WriteFile(secrets, buildDoc(t, FormatJSON, key, sampleDoc, docOptions{}), 0o600); err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(dir, "keys.txt")
	if err := os.WriteFile(idFile, []byte("# test\n"+key.identity+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := Open(Options{File: secrets, AgeKeyFile: idFile})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := b.Get(context.Background(), "stripe_key"); err != nil || string(v) != "sk_live_example" {
		t.Fatalf("identity file = %q, %v", v, err)
	}
	for name, o := range map[string]Options{
		"no file":        {AgeKey: key.identity},
		"no identity":    {File: secrets},
		"unknown format": {File: secrets, AgeKey: key.identity, Format: "toml"},
	} {
		if _, err := Open(o); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	ctx := context.Background()
	missing, _ := Open(Options{File: filepath.Join(dir, "none.json"), AgeKey: key.identity})
	if _, _, err := missing.Get(ctx, "a"); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing file = %v", err)
	}
	if _, err := missing.List(ctx, ""); !errors.Is(err, backend.ErrNotFound) {
		t.Fatalf("missing file list = %v", err)
	}
	noKey, _ := Open(Options{File: secrets, AgeKeyFile: filepath.Join(dir, "absent.txt")})
	if _, _, err := noKey.Get(ctx, "a"); err == nil {
		t.Fatal("a missing identity file was ignored")
	}
	badKey, _ := Open(Options{File: secrets, AgeKey: "not an identity"})
	if _, _, err := badKey.Get(ctx, "a"); err == nil {
		t.Fatal("a bad identity was accepted")
	}
	garbage := filepath.Join(dir, "g.json")
	_ = os.WriteFile(garbage, []byte("{"), 0o600)
	g, _ := Open(Options{File: garbage, AgeKey: key.identity})
	if _, err := g.List(ctx, ""); err == nil {
		t.Fatal("a garbage file listed")
	}
	huge := filepath.Join(dir, "huge.json")
	_ = os.WriteFile(huge, bytes.Repeat([]byte(" "), MaxFileSize+1), 0o600)
	h, _ := Open(Options{File: huge, AgeKey: key.identity})
	if _, _, err := h.Get(ctx, "a"); err == nil {
		t.Fatal("an oversized file was read")
	}
}

func TestFactory(t *testing.T) {
	key := newKey(t)
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, buildDoc(t, FormatJSON, key, sampleDoc, docOptions{}), 0o600); err != nil {
		t.Fatal(err)
	}
	f, ok := backend.Default.Get("sops")
	if !ok {
		t.Fatal("sops is not registered")
	}
	b, err := f(context.Background(), backend.BackendConfig{Name: "sops", Settings: map[string]interface{}{"file": path, "age_key": key.identity, "verify_mac": "false", "format": "json"}})
	if err != nil {
		t.Fatal(err)
	}
	if v, _, err := b.Get(context.Background(), "db/password"); err != nil || string(v) != "hunter2" {
		t.Fatalf("factory backend = %q, %v", v, err)
	}
	for name, s := range map[string]map[string]interface{}{
		"unknown key": {"file": path, "age_key": key.identity, "surprise": "x"},
		"no file":     {"age_key": key.identity},
	} {
		if _, err := f(context.Background(), backend.BackendConfig{Name: "sops", Settings: s}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestAgainstRealSops reads files the sops and age tools wrote. It runs where
// those tools are installed, and covers what the fixtures above cannot: the
// exact MAC, AAD and comment handling of the reference implementation.
func TestAgainstRealSops(t *testing.T) {
	sopsBin, err1 := exec.LookPath("sops")
	keygen, err2 := exec.LookPath("age-keygen")
	if err1 != nil || err2 != nil {
		t.Skip("sops and age-keygen are not installed")
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key.txt")
	if out, err := exec.Command(keygen, "-o", keyFile).CombinedOutput(); err != nil { //nolint:gosec // G204: a tool found on PATH, a path under TempDir
		t.Skipf("age-keygen: %v %s", err, out)
	}
	recipient := regexp.MustCompile(`age1[a-z0-9]+`).FindString(readFile(t, keyFile))
	ids, err := ParseIdentities(strings.NewReader(readFile(t, keyFile)))
	if err != nil {
		t.Fatal(err)
	}
	encrypt := func(name, in string, args ...string) []byte {
		src := filepath.Join(dir, name)
		if err := os.WriteFile(src, []byte(in), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(sopsBin, append([]string{"--encrypt", "--age", recipient}, append(args, src)...)...) //nolint:gosec // G204: see above
		out, err := cmd.Output()
		if err != nil {
			t.Skipf("sops --encrypt: %v", err)
		}
		return out
	}

	yml := encrypt("a.yaml", "db:\n  password: hunter2\n  port: 5432\n  ssl: true\n  ratio: 1.5\nlist:\n  - a\n  - b\nstripe_key: sk\npub_unencrypted: open\n")
	v, err := Decrypt(FormatYAML, yml, ids, DecryptOptions{})
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	want(t, v, "db/password", "hunter2")
	want(t, v, "db/port", "5432")
	want(t, v, "db/ssl", "true")
	want(t, v, "db/ratio", "1.5")
	want(t, v, "list/1", "b")
	want(t, v, "pub_unencrypted", "open")

	commented := encrypt("c.yaml", "# head of doc\n\n# key head\na: 1 # line\nb:\n  # inner head\n  c: x\n  d:\n    - p # lp\n    # item head\n    - q\n# foot\n")
	cv, err := Decrypt(FormatYAML, commented, ids, DecryptOptions{})
	if err != nil {
		t.Fatalf("yaml with comments: %v", err)
	}
	want(t, cv, "b/d/0", "p")
	want(t, cv, "b/d/1", "q")

	js := encrypt("a.json", `{"a":{"b":"x"},"n":3,"pub_unencrypted":"open","arr":[1,"s"]}`)
	jv, err := Decrypt(FormatJSON, js, ids, DecryptOptions{})
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	want(t, jv, "a/b", "x")
	want(t, jv, "arr/0", "1")

	env := encrypt("a.env", "A=one\nB=two words\n# a comment\nC=\"quoted\"\n", "--input-type", "dotenv", "--output-type", "dotenv")
	ev, err := Decrypt(FormatDotenv, env, ids, DecryptOptions{})
	if err != nil {
		t.Fatalf("dotenv: %v", err)
	}
	want(t, ev, "B", "two words")
	if paths, err := Paths(FormatDotenv, env); err != nil || !slices.Equal(paths, []string{"A", "B", "C"}) {
		t.Fatalf("dotenv paths = %v, %v", paths, err)
	}

	// The reference implementation's own MAC catches the same tampering.
	dropped := regexp.MustCompile(`(?m)^stripe_key: .*\n`).ReplaceAll(yml, nil)
	if _, err := Decrypt(FormatYAML, dropped, ids, DecryptOptions{}); !errors.Is(err, ErrMAC) {
		t.Fatalf("dropped value = %v", err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
