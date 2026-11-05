// Package merge edits a harness's configuration files without disturbing what
// the user wrote: unknown keys, key order and (for TOML and YAML) comments
// survive, and the previous file is saved next to it as <name>.keylatch.bak.
package merge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Object is a JSON object that remembers the order of its keys. Values are
// *Object, []any, string, json.Number, bool or nil.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Keys lists the keys in document order.
func (o *Object) Keys() []string { return slices.Clone(o.keys) }

// Get returns the value under key.
func (o *Object) Get(key string) (any, bool) {
	v, ok := o.vals[key]
	return v, ok
}

// Set stores v under key, keeping the key's place when it exists and appending
// it otherwise.
func (o *Object) Set(key string, v any) {
	if _, ok := o.vals[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// Delete removes key.
func (o *Object) Delete(key string) {
	if _, ok := o.vals[key]; !ok {
		return
	}
	delete(o.vals, key)
	o.keys = slices.DeleteFunc(o.keys, func(k string) bool { return k == key })
}

// Child returns the object under key. A missing key yields a new object that is
// attached to o; a key that holds anything but an object is an error, so a
// user's unexpected value is never overwritten.
func (o *Object) Child(key string) (*Object, error) {
	v, ok := o.vals[key]
	if !ok {
		c := NewObject()
		o.Set(key, c)
		return c, nil
	}
	c, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("existing %q value is not an object", key)
	}
	return c, nil
}

// List returns the array under key, or nil when the key is missing. A key that
// holds anything but an array is an error.
func (o *Object) List(key string) ([]any, error) {
	v, ok := o.vals[key]
	if !ok {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("existing %q value is not an array", key)
	}
	return l, nil
}

// ParseJSON reads a JSON document whose root is an object. An empty document
// is an empty object. A document that is not strict JSON (comments, trailing
// commas) is refused: rewriting it would drop what the user wrote.
func ParseJSON(data []byte) (*Object, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return NewObject(), nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, fmt.Errorf("not strict JSON (comments and trailing commas are not supported): %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("not strict JSON: data after the top-level value")
	}
	o, ok := v.(*Object)
	if !ok {
		return nil, errors.New("the top-level JSON value is not an object")
	}
	return o, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch delim {
	case '{':
		o := NewObject()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, _ := kt.(string)
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			if _, dup := o.vals[key]; dup {
				return nil, fmt.Errorf("duplicate key %q", key)
			}
			o.Set(key, v)
		}
		_, err := dec.Token()
		return o, err
	case '[':
		l := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		_, err := dec.Token()
		return l, err
	}
	return nil, fmt.Errorf("unexpected delimiter %v", delim)
}

// Encode writes o with the given indent, ending in a newline.
func (o *Object) Encode(indent string) []byte {
	var b bytes.Buffer
	encodeValue(&b, o, indent, 0)
	b.WriteByte('\n')
	return b.Bytes()
}

func encodeValue(b *bytes.Buffer, v any, indent string, depth int) {
	pad := func(n int) { b.WriteString("\n" + strings.Repeat(indent, n)) }
	switch t := v.(type) {
	case *Object:
		if len(t.keys) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			pad(depth + 1)
			writeScalar(b, k)
			b.WriteString(": ")
			encodeValue(b, t.vals[k], indent, depth+1)
		}
		pad(depth)
		b.WriteByte('}')
	case []any:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			pad(depth + 1)
			encodeValue(b, e, indent, depth+1)
		}
		pad(depth)
		b.WriteByte(']')
	default:
		writeScalar(b, t)
	}
}

func writeScalar(b *bytes.Buffer, v any) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		b.WriteString("null")
		return
	}
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

// DetectIndent returns the indentation the document uses, two spaces when it
// has none to copy.
func DetectIndent(data []byte) string {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed != "" && len(trimmed) < len(line) {
			return line[:len(line)-len(trimmed)]
		}
	}
	return "  "
}

// EditJSON parses doc, applies edit and re-encodes it with the document's own
// indentation. When edit changes nothing the document is returned byte for
// byte, so an install over an installed harness leaves the file alone.
func EditJSON(doc []byte, edit func(root *Object) error) ([]byte, error) {
	root, err := ParseJSON(doc)
	if err != nil {
		return nil, err
	}
	indent := DetectIndent(doc)
	before := root.Encode(indent)
	if err := edit(root); err != nil {
		return nil, err
	}
	after := root.Encode(indent)
	if bytes.Equal(before, after) {
		return doc, nil
	}
	return after, nil
}
