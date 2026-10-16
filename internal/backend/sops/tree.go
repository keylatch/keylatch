package sops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Format is the serialization of a sops file.
type Format string

// The formats a sops file can have.
const (
	FormatJSON   Format = "json"
	FormatYAML   Format = "yaml"
	FormatDotenv Format = "dotenv"
)

// kind is the shape of a tree node.
type kind int

const (
	scalarNode kind = iota
	mapNode
	listNode
	commentNode
)

// node is one element of a sops document. Mapping and list order is kept
// because the file's MAC covers the values in order.
type node struct {
	kind kind
	// text is a scalar's stored text: "ENC[...]" for an encrypted value, else
	// the plain value formatted the way sops hashes it.
	text string
	// keys and kids hold a mapping's entries, or a list's elements (keys empty).
	// A comment is a kid with an empty key and kind commentNode.
	keys []string
	kids []*node
}

// metadata is the "sops" section of a file.
type metadata struct {
	age               []ageRecipient
	lastModified      string
	mac               string
	macOnlyEncrypted  bool
	unencryptedSuffix string
}

type ageRecipient struct {
	recipient string
	enc       string
}

// ErrFormat means the file is not a well-formed sops document.
var ErrFormat = errors.New("sops: the file is not a sops document")

// DetectFormat picks the format from a file name.
func DetectFormat(name string) Format {
	switch {
	case strings.HasSuffix(name, ".json"):
		return FormatJSON
	case strings.HasSuffix(name, ".env"), strings.HasSuffix(name, ".dotenv"):
		return FormatDotenv
	}
	return FormatYAML
}

func parse(f Format, data []byte) (*node, *metadata, error) {
	switch f {
	case FormatJSON:
		return parseJSON(data)
	case FormatYAML:
		return parseYAML(data)
	case FormatDotenv:
		return parseDotenv(data)
	}
	return nil, nil, fmt.Errorf("sops: unknown format %q", f)
}

// plainText formats a plain (unencrypted) scalar the way sops hashes it.
func plainText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func (n *node) get(key string) *node {
	for i, k := range n.keys {
		if k == key && n.kids[i].kind != commentNode {
			return n.kids[i]
		}
	}
	return nil
}

func (n *node) add(key string, kid *node) {
	n.keys = append(n.keys, key)
	n.kids = append(n.kids, kid)
}

// addComments appends the lines of a comment block as comment nodes.
func (n *node) addComments(block string) {
	if block == "" {
		return
	}
	for _, line := range strings.Split(block, "\n") {
		n.add("", &node{kind: commentNode, text: strings.TrimPrefix(strings.TrimRight(line, "\r"), "#")})
	}
}

// splitSops removes the "sops" entry from the document root and reads it.
func splitSops(root *node) (*metadata, error) {
	var raw *node
	for i, k := range root.keys {
		if k == "sops" && root.kids[i].kind == mapNode {
			raw = root.kids[i]
			root.keys = append(root.keys[:i:i], root.keys[i+1:]...)
			root.kids = append(root.kids[:i:i], root.kids[i+1:]...)
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("%w: no sops section", ErrFormat)
	}
	return metadataFromTree(raw)
}

// ---- JSON

func parseJSON(data []byte) (*node, *metadata, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := readJSON(dec)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if root.kind != mapNode {
		return nil, nil, ErrFormat
	}
	md, err := splitSops(root)
	return root, md, err
}

func readJSON(dec *json.Decoder) (*node, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		n := &node{kind: mapNode}
		if t == '[' {
			n.kind = listNode
		}
		for dec.More() {
			key := ""
			if t == '{' {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				s, ok := kt.(string)
				if !ok {
					return nil, errors.New("non-string key")
				}
				key = s
			}
			child, err := readJSON(dec)
			if err != nil {
				return nil, err
			}
			n.add(key, child)
		}
		_, err := dec.Token()
		return n, err
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return &node{text: plainText(i)}, nil
		}
		f, err := t.Float64()
		if err != nil {
			return nil, err
		}
		return &node{text: plainText(f)}, nil
	case string:
		return &node{text: t}, nil
	case bool:
		return &node{text: plainText(t)}, nil
	case nil:
		return &node{}, nil
	}
	return nil, errors.New("unexpected JSON token")
}

// ---- YAML

func parseYAML(data []byte) (*node, *metadata, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, ErrFormat
	}
	root := &node{}
	root.addComments(doc.HeadComment)
	if err := yamlInto(root, doc.Content[0]); err != nil {
		return nil, nil, err
	}
	root.addComments(doc.FootComment)
	md, err := splitSops(root)
	return root, md, err
}

func yamlInto(n *node, y *yaml.Node) error {
	switch y.Kind {
	case yaml.MappingNode:
		n.kind = mapNode
		n.addComments(y.HeadComment)
		for i := 0; i+1 < len(y.Content); i += 2 {
			k, v := y.Content[i], y.Content[i+1]
			n.addComments(k.HeadComment)
			child := &node{}
			if err := yamlInto(child, v); err != nil {
				return err
			}
			n.add(k.Value, child)
			n.addComments(k.LineComment)
			if v.Kind == yaml.ScalarNode {
				n.addComments(v.LineComment)
			}
			n.addComments(k.FootComment)
		}
	case yaml.SequenceNode:
		n.kind = listNode
		for _, item := range y.Content {
			n.addComments(item.HeadComment)
			child := &node{}
			if err := yamlInto(child, item); err != nil {
				return err
			}
			n.add("", child)
			if item.Kind == yaml.ScalarNode {
				n.addComments(item.LineComment)
			}
		}
	case yaml.ScalarNode:
		n.kind = scalarNode
		if y.Tag == "!!str" || y.Tag == "" || strings.HasPrefix(y.Value, "ENC[") {
			n.text = y.Value
			return nil
		}
		var v any
		if err := y.Decode(&v); err != nil {
			return err
		}
		n.text = plainText(v)
	case yaml.AliasNode:
		return errors.New("sops: YAML aliases are not supported in a secrets file")
	default:
		return ErrFormat
	}
	return nil
}

// ---- dotenv

func parseDotenv(data []byte) (*node, *metadata, error) {
	root := &node{kind: mapNode}
	meta := &node{kind: mapNode}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "#"):
			root.addComments(line)
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, nil, fmt.Errorf("%w: line without '='", ErrFormat)
		}
		v = strings.ReplaceAll(v, `\n`, "\n")
		if name, ok := strings.CutPrefix(k, "sops_"); ok {
			insertFlat(meta, strings.Split(name, "__"), v)
			continue
		}
		root.add(k, &node{text: v})
	}
	if len(meta.keys) == 0 {
		return nil, nil, fmt.Errorf("%w: no sops metadata", ErrFormat)
	}
	md, err := metadataFromTree(meta)
	return root, md, err
}

// insertFlat rebuilds the nested metadata sops flattens into dotenv names:
// "age__list_0__map_enc" is age[0].enc.
func insertFlat(root *node, parts []string, value string) {
	cur := root
	for i, p := range parts {
		last := i == len(parts)-1
		if idxText, isList := strings.CutPrefix(p, "list_"); isList {
			idx, err := strconv.Atoi(idxText)
			if err != nil || idx < 0 || idx > 1024 {
				return
			}
			cur.kind = listNode
			for len(cur.kids) <= idx {
				cur.add("", &node{})
			}
			if last {
				cur.kids[idx].text = value
				return
			}
			cur = cur.kids[idx]
			continue
		}
		key := strings.TrimPrefix(p, "map_")
		cur.kind = mapNode
		child := cur.get(key)
		if child == nil {
			child = &node{}
			cur.add(key, child)
		}
		if last {
			child.text = value
			return
		}
		cur = child
	}
}

// ---- metadata

func metadataFromTree(m *node) (*metadata, error) {
	md := &metadata{unencryptedSuffix: "_unencrypted"}
	if v := m.get("lastmodified"); v != nil {
		md.lastModified = v.text
	}
	if v := m.get("mac"); v != nil {
		md.mac = v.text
	}
	if v := m.get("unencrypted_suffix"); v != nil && v.text != "" {
		md.unencryptedSuffix = v.text
	}
	if v := m.get("mac_only_encrypted"); v != nil {
		md.macOnlyEncrypted = strings.EqualFold(v.text, "true")
	}
	if list := m.get("age"); list != nil {
		for _, e := range list.kids {
			r := ageRecipient{}
			if v := e.get("recipient"); v != nil {
				r.recipient = v.text
			}
			if v := e.get("enc"); v != nil {
				r.enc = v.text
			}
			if r.enc != "" {
				md.age = append(md.age, r)
			}
		}
	}
	if md.mac == "" || md.lastModified == "" {
		return nil, fmt.Errorf("%w: the sops section has no mac or lastmodified", ErrFormat)
	}
	return md, nil
}

// readAll is io.ReadAll bounded so a huge file cannot exhaust the daemon.
func readAll(r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("sops: the file is larger than %d bytes", limit)
	}
	return b, nil
}
