// Package template defines the schema types for provider template actions.
// These types extend the registry's GatewayAction with a richer parameter model
// that supports typed, located parameters for direct HTTP dispatch (EPIC-20).
package template

import (
	"fmt"
	"strings"
)

// validMethods is the closed set of allowed HTTP methods for actions.
var validMethods = map[string]struct{}{
	"GET":    {},
	"POST":   {},
	"PUT":    {},
	"DELETE": {},
	"PATCH":  {},
}

// validInValues is the closed set of valid "in" values for ParamSpec.
var validInValues = map[string]struct{}{
	"query": {},
	"path":  {},
	"body":  {},
}

// ParamSpec describes a single parameter accepted by an Action.
type ParamSpec struct {
	// Type is the JSON-schema-style primitive type: "string", "integer", "boolean".
	Type string `yaml:"type"`
	// Required indicates that the caller must supply this parameter.
	Required bool `yaml:"required"`
	// In describes where the parameter is placed in the HTTP request.
	// Valid values: "query", "path", "body".
	In string `yaml:"in"`
}

// Action describes a single scoped HTTP operation exposed by a provider template.
// It is stored under the "actions" YAML key on a ConnectionTemplate.
type Action struct {
	// Method is the HTTP method (GET, POST, PUT, DELETE, PATCH).
	Method string `yaml:"method"`
	// Path is the URL path, e.g. "/v1/models" or "/v1/files/{file_id}".
	// Must start with "/".
	Path string `yaml:"path"`
	// Params is the optional named parameter schema.
	Params map[string]ParamSpec `yaml:"params,omitempty"`
	// ResponseSchema is an optional JSON schema reference for the response body.
	ResponseSchema string `yaml:"response_schema,omitempty"`
}

// Validate checks that a is well-formed. It returns a non-nil error on the first
// violation found.
func (a Action) Validate(name string) error {
	if _, ok := validMethods[strings.ToUpper(a.Method)]; !ok {
		return fmt.Errorf("action %q: method %q is not one of GET/POST/PUT/DELETE/PATCH", name, a.Method)
	}
	if !strings.HasPrefix(a.Path, "/") {
		return fmt.Errorf("action %q: path %q must start with \"/\"", name, a.Path)
	}
	for pName, spec := range a.Params {
		if spec.In != "" {
			if _, ok := validInValues[spec.In]; !ok {
				return fmt.Errorf("action %q: param %q has invalid \"in\" value %q", name, pName, spec.In)
			}
		}
	}
	return nil
}

// ValidateActions validates all actions in the map and returns the first error.
func ValidateActions(actions map[string]Action) error {
	for name, a := range actions {
		if err := a.Validate(name); err != nil {
			return err
		}
	}
	return nil
}
