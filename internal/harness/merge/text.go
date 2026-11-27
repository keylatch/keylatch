package merge

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Markers delimit the part of a TOML or Markdown file that Keylatch owns.
// Everything outside them is never touched, so the user's comments and layout
// survive.
const (
	BlockBegin = "# >>> keylatch >>>"
	BlockEnd   = "# <<< keylatch <<<"

	MarkdownBegin = "<!-- keylatch:begin -->"
	MarkdownEnd   = "<!-- keylatch:end -->"
)

// TOMLBlock puts body between the Keylatch markers: in place when the block
// exists, at the end of the file otherwise. The result must still be valid TOML,
// which fails when the user already defines the same table outside the block.
func TOMLBlock(doc []byte, body string) ([]byte, error) {
	if err := checkTOML(doc, "the existing file"); err != nil {
		return nil, err
	}
	out, err := replaceBlock(doc, BlockBegin, BlockEnd, strings.TrimRight(body, "\n"))
	if err != nil {
		return nil, err
	}
	if err := checkTOML(out, "the file with the Keylatch block"); err != nil {
		return nil, fmt.Errorf("%w (a table the block defines may already exist outside it)", err)
	}
	return out, nil
}

// RemoveTOMLBlock deletes the Keylatch block and reports whether there was one.
func RemoveTOMLBlock(doc []byte) ([]byte, bool, error) {
	return removeBlock(doc, BlockBegin, BlockEnd)
}

// MarkdownBlock puts body between the Keylatch markers of a Markdown file.
func MarkdownBlock(doc []byte, body string) ([]byte, error) {
	return replaceBlock(doc, MarkdownBegin, MarkdownEnd, strings.TrimRight(body, "\n"))
}

// RemoveMarkdownBlock deletes the Keylatch block and reports whether there was one.
func RemoveMarkdownBlock(doc []byte) ([]byte, bool, error) {
	return removeBlock(doc, MarkdownBegin, MarkdownEnd)
}

func checkTOML(doc []byte, what string) error {
	var sink map[string]any
	if _, err := toml.NewDecoder(bytes.NewReader(doc)).Decode(&sink); err != nil {
		return fmt.Errorf("%s is not valid TOML: %w", what, err)
	}
	return nil
}

func blockBounds(doc []byte, begin, end string) (start, stop int, found bool, err error) {
	s := string(doc)
	start = strings.Index(s, begin)
	if start < 0 {
		return 0, 0, false, nil
	}
	if strings.Count(s, begin) != 1 {
		return 0, 0, false, fmt.Errorf("more than one %q marker", begin)
	}
	rel := strings.Index(s[start:], end)
	if rel < 0 {
		return 0, 0, false, fmt.Errorf("%q has no closing %q", begin, end)
	}
	stop = start + rel + len(end)
	if stop < len(s) && s[stop] == '\n' {
		stop++
	}
	return start, stop, true, nil
}

func replaceBlock(doc []byte, begin, end, body string) ([]byte, error) {
	block := begin + "\n" + body + "\n" + end + "\n"
	start, stop, found, err := blockBounds(doc, begin, end)
	if err != nil {
		return nil, err
	}
	if found {
		return append(append(append([]byte{}, doc[:start]...), block...), doc[stop:]...), nil
	}
	out := bytes.Clone(doc)
	if len(out) > 0 && !bytes.HasSuffix(out, []byte("\n")) {
		out = append(out, '\n')
	}
	if len(out) > 0 {
		out = append(out, '\n')
	}
	return append(out, block...), nil
}

func removeBlock(doc []byte, begin, end string) ([]byte, bool, error) {
	start, stop, found, err := blockBounds(doc, begin, end)
	if err != nil || !found {
		return doc, false, err
	}
	// Drop the blank line the install added in front of the block.
	if start >= 2 && bytes.Equal(doc[start-2:start], []byte("\n\n")) {
		start--
	}
	return append(append([]byte{}, doc[:start]...), doc[stop:]...), true, nil
}

// EditYAML sets the value at path (creating missing mappings on the way) in a
// YAML document, keeping its comments and key order. The value replaces any
// existing one only when it differs, so an install over an installed harness
// returns the document unchanged.
func EditYAML(doc []byte, path []string, value any) ([]byte, error) {
	if len(path) == 0 {
		return nil, errors.New("empty YAML path")
	}
	var root yaml.Node
	if len(bytes.TrimSpace(doc)) > 0 {
		if err := yaml.Unmarshal(doc, &root); err != nil {
			return nil, fmt.Errorf("not valid YAML: %w", err)
		}
	}
	if root.Kind == 0 {
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("the top-level YAML value is not a mapping")
	}
	var want yaml.Node
	if err := want.Encode(value); err != nil {
		return nil, err
	}
	m := root.Content[0]
	for i, key := range path {
		last := i == len(path)-1
		idx := -1
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == key {
				idx = j + 1
				break
			}
		}
		switch {
		case idx < 0 && last:
			m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, &want)
		case idx < 0:
			child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, child)
			m = child
		case last:
			if !sameYAML(m.Content[idx], &want) {
				want.HeadComment, want.LineComment, want.FootComment = m.Content[idx].HeadComment, m.Content[idx].LineComment, m.Content[idx].FootComment
				m.Content[idx] = &want
			}
		default:
			if m.Content[idx].Kind != yaml.MappingNode {
				return nil, fmt.Errorf("existing %q value is not a mapping", key)
			}
			m = m.Content[idx]
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	if bytes.Equal(canonicalYAML(doc), canonicalYAML(out.Bytes())) {
		return doc, nil
	}
	return out.Bytes(), nil
}

func sameYAML(a, b *yaml.Node) bool {
	x, _ := yaml.Marshal(a)
	y, _ := yaml.Marshal(b)
	return bytes.Equal(x, y)
}

func canonicalYAML(doc []byte) []byte {
	var root yaml.Node
	if yaml.Unmarshal(doc, &root) != nil {
		return doc
	}
	out, err := yaml.Marshal(&root)
	if err != nil {
		return doc
	}
	return out
}
