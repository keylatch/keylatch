package hostimport

import (
	"fmt"
	"strconv"
	"strings"
)

// parseTOML reads the small part of TOML an agent's config uses: [table] and
// [a.b] headers, and key = value with strings, booleans, integers and arrays
// of those, which may span lines. Anything else is an error, so a setting the
// importer does not understand is never silently read as absent.
func parseTOML(src string) (map[string]any, error) {
	root := map[string]any{}
	cur := root
	lines := strings.Split(src, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripComment(lines[i]))
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "[["):
			return nil, fmt.Errorf("%w: arrays of tables (line %d)", errTOML, i+1)
		case strings.HasPrefix(line, "["):
			name, ok := strings.CutSuffix(strings.TrimPrefix(line, "["), "]")
			if !ok {
				return nil, fmt.Errorf("%w: line %d", errTOML, i+1)
			}
			cur = root
			for _, part := range strings.Split(name, ".") {
				part = strings.Trim(strings.TrimSpace(part), `"`)
				next, ok := cur[part].(map[string]any)
				if !ok {
					next = map[string]any{}
					cur[part] = next
				}
				cur = next
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: line %d", errTOML, i+1)
		}
		value = strings.TrimSpace(value)
		for strings.HasPrefix(value, "[") && !balanced(value) && i+1 < len(lines) {
			i++
			value += " " + strings.TrimSpace(stripComment(lines[i]))
		}
		v, err := tomlValue(value)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		cur[strings.Trim(strings.TrimSpace(key), `"`)] = v
	}
	return root, nil
}

// stripComment removes a # comment that is not inside a string.
func stripComment(line string) string {
	var quote rune
	for i, r := range line {
		switch {
		case quote != 0:
			if r == quote && (i == 0 || line[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '#':
			return line[:i]
		}
	}
	return line
}

func balanced(s string) bool {
	depth := 0
	var quote rune
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '[':
			depth++
		case r == ']':
			depth--
		}
	}
	return depth <= 0
}

func tomlValue(s string) (any, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "true":
		return true, nil
	case s == "false":
		return false, nil
	case strings.HasPrefix(s, `"`):
		return strconv.Unquote(s)
	case strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) >= 2:
		return s[1 : len(s)-1], nil
	case strings.HasPrefix(s, "["):
		inner, ok := strings.CutSuffix(strings.TrimPrefix(s, "["), "]")
		if !ok {
			return nil, fmt.Errorf("%w: unterminated array", errTOML)
		}
		var out []any
		for _, part := range splitTop(inner) {
			if strings.TrimSpace(part) == "" {
				continue
			}
			v, err := tomlValue(part)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	return nil, fmt.Errorf("%w: value %q", errTOML, s)
}

// splitTop splits on commas outside strings and nested arrays.
func splitTop(s string) []string {
	var out []string
	depth, start := 0, 0
	var quote rune
	for i, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
		case r == '[':
			depth++
		case r == ']':
			depth--
		case r == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
