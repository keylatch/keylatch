// Package customsecret holds user-defined secrets for services that have no
// provider template: the value (or an external-store reference) lives in the
// configured backend, and the host, path, method and injection rules live in a
// small metadata file that never contains the value.
package customsecret

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Injection kinds.
const (
	InjectHeader = "header"
	InjectQuery  = "query"
	InjectBasic  = "basic"
)

// ValuePlaceholder marks where the credential goes in a header format.
const ValuePlaceholder = "{value}"

var (
	nameRe       = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	labelRe      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	headerNameRe = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
	queryParamRe = regexp.MustCompile(`^[A-Za-z0-9_.\[\]-]{1,64}$`)
	envNameRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
)

// internalSuffixes are names that resolve inside a private network or only locally.
var internalSuffixes = []string{
	".localhost", ".local", ".localdomain", ".internal", ".intranet", ".lan", ".home", ".home.arpa", ".corp", ".private",
}

// forbiddenHeaders are request-framing and routing headers the gateway owns.
var forbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"te": true, "trailer": true, "upgrade": true, "proxy-authorization": true, "proxy-authenticate": true,
	"cookie": true, "set-cookie": true, "forwarded": true,
}

var allowedMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true,
}

// ValidateName checks the kebab-case secret name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("name %q must match %s (lowercase letters, digits and hyphens, starting with a letter)", name, nameRe)
	}
	return nil
}

// NormalizeHost validates one host entry and returns its lowercase form.
// Only HTTPS destinations are supported, so no scheme, port, path or credentials are accepted.
func NormalizeHost(raw string) (string, error) {
	host := strings.ToLower(strings.TrimSpace(raw))
	if host == "" {
		return "", errors.New("host is empty")
	}
	if strings.ContainsAny(host, "/:@?#\\ \t\r\n[]") {
		return "", fmt.Errorf("host %q must be a bare DNS name: no scheme, port, path, credentials or IP literal (HTTPS only)", raw)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", fmt.Errorf("host %q is an IP literal; use a DNS name", raw)
	}

	wildcard := strings.HasPrefix(host, "*.")
	base := strings.TrimPrefix(host, "*.")
	if strings.Contains(base, "*") {
		return "", fmt.Errorf("host %q: a wildcard is only allowed as the single leftmost label (*.example.com)", raw)
	}
	if len(base) > 253 || strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".") {
		return "", fmt.Errorf("host %q is not a valid DNS name", raw)
	}
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return "", fmt.Errorf("host %q must have at least two labels", raw)
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", fmt.Errorf("host %q has an invalid label %q", raw, l)
		}
	}
	// An all-numeric last label would be read as a legacy IPv4 form (2130706433, 127.1).
	if last := labels[len(labels)-1]; strings.Trim(last, "0123456789") == "" {
		return "", fmt.Errorf("host %q must end in a DNS suffix, not a number", raw)
	}
	if base == "localhost" {
		return "", fmt.Errorf("host %q is local to this machine", raw)
	}
	for _, s := range internalSuffixes {
		if strings.HasSuffix(base, s) {
			return "", fmt.Errorf("host %q is in the private suffix %q", raw, s)
		}
	}
	if suffix, _ := publicsuffix.PublicSuffix(base); suffix == base {
		if wildcard {
			return "", fmt.Errorf("host %q: wildcards on the public suffix %q would cover unrelated sites", raw, base)
		}
		return "", fmt.Errorf("host %q is a public suffix, not a service host", raw)
	}
	return host, nil
}

// NormalizePath validates one allowed path prefix and returns its canonical form.
func NormalizePath(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path %q must start with /", raw)
	}
	if len(p) > 256 || strings.ContainsAny(p, "?#%\\ \t\r\n") || strings.Contains(p, "//") {
		return "", fmt.Errorf("path %q must be a plain prefix: no query, fragment, encoding, spaces or empty segments", raw)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "", fmt.Errorf("path %q must not contain . or .. segments", raw)
		}
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return p, nil
}

// NormalizeMethod validates one HTTP method and returns its uppercase form.
func NormalizeMethod(raw string) (string, error) {
	m := strings.ToUpper(strings.TrimSpace(raw))
	if !allowedMethods[m] {
		return "", fmt.Errorf("method %q is not one of GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS", raw)
	}
	return m, nil
}

// ParseHeaderRule parses `Name: format with {value}` into an injection rule.
func ParseHeaderRule(spec string) (Injection, error) {
	name, format, ok := strings.Cut(spec, ":")
	name = strings.TrimSpace(name)
	format = strings.TrimSpace(format)
	if !ok || name == "" || format == "" {
		return Injection{}, fmt.Errorf("header rule %q must look like \"Name: format with %s\"", spec, ValuePlaceholder)
	}
	in := Injection{Kind: InjectHeader, Name: name, Format: format}
	return in, in.validate()
}

func (in Injection) validate() error {
	switch in.Kind {
	case InjectHeader:
		if !headerNameRe.MatchString(in.Name) {
			return fmt.Errorf("header name %q is not a valid HTTP header name", in.Name)
		}
		if forbiddenHeaders[strings.ToLower(in.Name)] {
			return fmt.Errorf("header %q is managed by the gateway and cannot carry a secret", in.Name)
		}
		if strings.Count(in.Format, ValuePlaceholder) != 1 {
			return fmt.Errorf("header format must contain %s exactly once", ValuePlaceholder)
		}
		for _, r := range in.Format {
			if r < 0x20 || r > 0x7e {
				return errors.New("header format must be printable ASCII")
			}
		}
	case InjectQuery:
		if !queryParamRe.MatchString(in.Name) {
			return fmt.Errorf("query parameter %q is not valid", in.Name)
		}
		if in.Format != "" {
			return errors.New("query injection takes no format")
		}
	case InjectBasic:
		if in.Name == "" || len(in.Name) > 128 || strings.ContainsAny(in.Name, ":\r\n\x00") {
			return errors.New("basic user must be 1-128 characters without ':' or control characters")
		}
		if in.Format != "" {
			return errors.New("basic injection takes no format")
		}
	default:
		return fmt.Errorf("injection kind %q must be header, query or basic", in.Kind)
	}
	return nil
}

// ValidateBaseURLEnv checks the env var that receives the gateway URL.
func ValidateBaseURLEnv(name string) error {
	if !envNameRe.MatchString(name) {
		return fmt.Errorf("env var %q must be upper-case letters, digits and underscores", name)
	}
	for _, p := range []string{"KEYLATCH_", "LD_", "DYLD_"} {
		if strings.HasPrefix(name, p) {
			return fmt.Errorf("env var %q is reserved", name)
		}
	}
	switch name {
	case "PATH", "HOME", "SHELL", "USER", "IFS", "PWD", "TMPDIR", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "BASH_ENV", "ENV":
		return fmt.Errorf("env var %q is reserved", name)
	}
	return nil
}

// ValidateValue rejects values that cannot be sent as an HTTP credential.
func ValidateValue(v []byte) error {
	if len(v) == 0 {
		return errors.New("value is empty")
	}
	for _, b := range v {
		if b < 0x20 || b == 0x7f {
			return errors.New("value must not contain control characters or line breaks")
		}
	}
	return nil
}
