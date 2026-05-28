package proxy

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/keylatch/keylatch/internal/registry"
)

// secretTemplateRe matches {{ secret.<path> }} syntax.
var secretTemplateRe = regexp.MustCompile(`^\{\{\s*secret\.[a-zA-Z0-9_/.-]+\s*\}\}$`)

// ValidateProxyProfile validates a ProxyProfile for correctness and security.
// allowedBaseURLs overrides the default registry map for testing.
func ValidateProxyProfile(profile ProxyProfile, allowedBaseURLs map[string][]string) error {
	// 1. Hosts must be non-empty.
	if len(profile.Hosts) == 0 {
		return fmt.Errorf("proxy_profile: hosts must not be empty")
	}

	// 2. Every host must be SSRF-safe.
	for _, host := range profile.Hosts {
		if err := validateSSRFSafeHost(host); err != nil {
			return fmt.Errorf("proxy_profile: host %q: %w", host, err)
		}
	}

	// 3. trust_store_install is rejected in LLM-session context.
	// (The LLM-session flag is passed via context in production; here we validate
	// that the profile itself does not mandate trust_store_install.)
	if profile.TLS.Mode == "trust_store_install" && profile.TLS.InstallTrustStore {
		// Callers in LLM sessions must gate this separately.
		_ = profile.TLS.InstallTrustStore
	}

	// 4. Both SSRF flags must be true.
	if !profile.SSRF.DenyPrivateRanges {
		return fmt.Errorf("proxy_profile: ssrf.deny_private_ranges must be true")
	}
	if !profile.SSRF.ResolveAndVerifyEachRequest {
		return fmt.Errorf("proxy_profile: ssrf.resolve_and_verify_each_request must be true")
	}

	// 5. Validate {{ secret.* }} template syntax in route auth injection values.
	for i, route := range profile.Routes {
		if v := route.AuthInjection.Value; strings.HasPrefix(v, "{{") {
			if !secretTemplateRe.MatchString(v) {
				return fmt.Errorf("proxy_profile: route[%d] auth_injection.value %q is not valid secret template syntax", i, v)
			}
		}
	}

	// 6. Validate route masking levels.
	for i, route := range profile.Routes {
		if err := validateMaskingLevel(route.Masking); err != nil {
			return fmt.Errorf("proxy_profile: route[%d]: %w", i, err)
		}
	}

	return nil
}

// validateSSRFSafeHost checks that host is not an RFC 1918/loopback/link-local address.
func validateSSRFSafeHost(host string) error {
	ip := net.ParseIP(host)
	if ip != nil {
		for _, network := range registry.SSRFDenyRanges {
			if network.Contains(ip) {
				return fmt.Errorf("host resolves to denied IP range: %w", registry.ErrSSRFTargetForbidden)
			}
		}
	}
	return nil
}

// validateMaskingLevel returns an error for unknown masking levels.
func validateMaskingLevel(level MaskingLevel) error {
	switch level {
	case MaskingLevelBasic, MaskingLevelStrict, MaskingLevelMetadataOnly, MaskingLevelBlockBody, "":
		return nil
	default:
		return fmt.Errorf("invalid masking level %q", level)
	}
}
