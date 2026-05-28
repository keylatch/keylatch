package registry_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/registry"
)

// TestFieldTagsAreConsistent uses reflection to assert that for every exported
// field in ConnectionTemplate (and nested structs), both json and yaml tags are
// present and their key names are identical (ignoring omitempty/inline options).
func TestFieldTagsAreConsistent(t *testing.T) {
	t.Helper()
	visited := map[reflect.Type]bool{}
	checkType(t, reflect.TypeOf(registry.ConnectionTemplate{}), visited)
}

// checkType walks all exported fields of a struct type recursively.
func checkType(t *testing.T, typ reflect.Type, visited map[reflect.Type]bool) {
	t.Helper()
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return
	}
	if visited[typ] {
		return
	}
	visited[typ] = true

	for i := range typ.NumField() {
		field := typ.Field(i)
		if !field.IsExported() {
			continue
		}

		jsonTag := field.Tag.Get("json")
		yamlTag := field.Tag.Get("yaml")

		if jsonTag == "" || jsonTag == "-" {
			t.Errorf("%s.%s: missing json tag", typ.Name(), field.Name)
			continue
		}
		if yamlTag == "" || yamlTag == "-" {
			t.Errorf("%s.%s: missing yaml tag", typ.Name(), field.Name)
			continue
		}

		jsonKey := strings.Split(jsonTag, ",")[0]
		yamlKey := strings.Split(yamlTag, ",")[0]

		if jsonKey != yamlKey {
			t.Errorf("%s.%s: json key %q != yaml key %q", typ.Name(), field.Name, jsonKey, yamlKey)
		}

		// Recurse into nested struct types.
		ft := field.Type
		if ft.Kind() == reflect.Ptr {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct {
			checkType(t, ft, visited)
		}
		// Also check slice element types.
		if ft.Kind() == reflect.Slice {
			et := ft.Elem()
			if et.Kind() == reflect.Ptr {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				checkType(t, et, visited)
			}
		}
	}
}
