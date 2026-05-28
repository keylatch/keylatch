package jcs_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/jcs"
)

type vector struct {
	Description string `json:"description"`
	Input       string `json:"input"`
	Expected    string `json:"expected"`
}

func TestRFC8785Vectors(t *testing.T) {
	data, err := os.ReadFile("testdata/rfc8785-vectors.json")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse testdata: %v", err)
	}

	for _, v := range vectors {
		v := v
		t.Run(v.Description, func(t *testing.T) {
			// Parse input as generic JSON.
			var parsed any
			d := json.NewDecoder(bytes.NewReader([]byte(v.Input)))
			d.UseNumber()
			if err := d.Decode(&parsed); err != nil {
				t.Fatalf("parse input: %v", err)
			}

			got, err := jcs.MarshalRaw(parsed)
			if err != nil {
				t.Fatalf("MarshalRaw: %v", err)
			}

			if string(got) != v.Expected {
				t.Errorf("got:  %s\nwant: %s", got, v.Expected)
			}
		})
	}
}

func TestMarshalDeterministic(t *testing.T) {
	input := map[string]any{
		"z":     "last",
		"a":     "first",
		"m":     42,
		"n":     true,
		"inner": map[string]any{"y": 1, "x": 2},
	}

	var first []byte
	for i := 0; i < 100; i++ {
		got, err := jcs.Marshal(input)
		if err != nil {
			t.Fatalf("Marshal iteration %d: %v", i, err)
		}
		if i == 0 {
			first = got
		} else if !bytes.Equal(first, got) {
			t.Fatalf("non-deterministic output at iteration %d:\nfirst: %s\ngot:   %s", i, first, got)
		}
	}
}

func TestMarshalSortedKeys(t *testing.T) {
	input := map[string]any{
		"z": 1,
		"a": 2,
		"m": 3,
	}
	got, err := jcs.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"a":2,"m":3,"z":1}`
	if string(got) != want {
		t.Errorf("got: %s, want: %s", got, want)
	}
}

func TestMarshalNoWhitespace(t *testing.T) {
	input := map[string]any{"k": "v"}
	got, err := jcs.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, b := range got {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			t.Errorf("output contains whitespace: %q", got)
		}
	}
}
