package registry

import "testing"

// FuzzTemplateParse feeds arbitrary bytes to the template validator and parser.
// Neither may panic, and a template that validates must also parse and pass the
// binding checks the registry applies before it registers one.
func FuzzTemplateParse(f *testing.F) {
	f.Add([]byte("name: x\n"))
	f.Add([]byte("provider: [unclosed\n"))
	f.Add([]byte("a: &a [*a]\n"))
	f.Add([]byte("TODO: replace\n"))
	f.Add([]byte("{\"name\": 1}"))
	f.Add([]byte("\x00\xff"))

	f.Fuzz(func(t *testing.T, data []byte) {
		if err := ValidateTemplateBytes(data); err != nil {
			return
		}
		tmpl, err := parseTemplate(data)
		if err != nil {
			return
		}
		_ = ValidateBindings(tmpl)
		_ = ValidateDenyRoutes(tmpl)
	})
}
