// Package runtime provides the runtime mode resolver for credential injection.
package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/keylatch/keylatch/internal/registry"
)

// ErrModeNotSupported is returned when the caller requests a runtime mode
// that is not listed in the provider template's supported set.
var ErrModeNotSupported = errors.New("runtime: requested mode not supported by provider")

// ResolveRequest carries the caller-supplied context for mode selection.
type ResolveRequest struct {
	// RequestedMode is the runtime mode the caller explicitly requested.
	// Empty string triggers automatic selection via the fallback hierarchy.
	RequestedMode RuntimeMode
	// ConnectionSlug identifies the provider template to consult.
	ConnectionSlug string
}

// RuntimeDecision is the output of Resolve: the chosen runtime mode and the
// reason it was selected.
type RuntimeDecision struct {
	// Mode is the selected RuntimeMode.
	Mode RuntimeMode
	// Reason describes why this mode was chosen (for logging, not security).
	Reason string
	// CredentialShape describes the shape of the credential that will be injected.
	CredentialShape CredentialDelivery
}

// CredentialDelivery categorises what kind of credential reaches the child.
type CredentialDelivery string

const (
	DeliveryKeylatchSessionToken CredentialDelivery = "keylatch_session_token"
	DeliveryProviderEphemeral    CredentialDelivery = "provider_ephemeral"
	DeliveryProviderRoot         CredentialDelivery = "provider_root"
)

// Resolve selects the runtime mode for an execution request.
//
// Selection order:
//  1. Removed modes check — if RequestedMode is in removedModes, return ErrModeRemoved.
//  2. Explicit caller request — if RequestedMode is set, it must appear in
//     tmpl.RuntimeSupport.Supported or ErrModeNotSupported is returned
//     (no silent downgrade).
//  3. Provider preferred mode — tmpl.RuntimeSupport.Preferred.
//  4. Fallback hierarchy: gateway_typed → gateway_sdk → direct_brokered → gateway_proxy.
//
// If no mode can be selected, ErrModeNotSupported is returned.
func Resolve(_ context.Context, req ResolveRequest, tmpl registry.ConnectionTemplate) (RuntimeDecision, error) {
	// Step 1: check removed modes before anything else.
	if req.RequestedMode != "" {
		if hint, removed := removedModes[string(req.RequestedMode)]; removed {
			return RuntimeDecision{
				Mode:   req.RequestedMode,
				Reason: hint,
			}, fmt.Errorf("%w: %s", ErrModeRemoved, hint)
		}
	}

	supported := supportedSet(tmpl)

	if req.RequestedMode != "" {
		if !supported[req.RequestedMode] {
			return RuntimeDecision{}, ErrModeNotSupported
		}
		return RuntimeDecision{
			Mode:            req.RequestedMode,
			Reason:          "explicit request",
			CredentialShape: shapeFor(req.RequestedMode),
		}, nil
	}

	if tmpl.RuntimeSupport.Preferred != "" {
		preferred := RuntimeMode(tmpl.RuntimeSupport.Preferred)
		// If Preferred is not in Supported, fall through silently to the hierarchy.
		// This is intentional: registry validation (AllModes in TestRuntimeSupportContainsOnlyValidModes)
		// prevents bad data from reaching production; a missing entry here means the
		// provider template is misconfigured and the fallback hierarchy is the safe recovery.
		if supported[preferred] {
			return RuntimeDecision{
				Mode:            preferred,
				Reason:          "provider preferred",
				CredentialShape: shapeFor(preferred),
			}, nil
		}
	}

	// Fallback hierarchy (v1.0.0 set — direct_classic removed).
	for _, m := range []RuntimeMode{
		RuntimeGatewayTyped,
		RuntimeGatewaySDK,
		RuntimeDirectBrokered,
		RuntimeGatewayProxy,
	} {
		if supported[m] {
			return RuntimeDecision{
				Mode:            m,
				Reason:          "fallback hierarchy",
				CredentialShape: shapeFor(m),
			}, nil
		}
	}

	return RuntimeDecision{}, ErrModeNotSupported
}

// supportedSet converts the registry slice to a fast-lookup map, using the
// runtime package's RuntimeMode type.
func supportedSet(tmpl registry.ConnectionTemplate) map[RuntimeMode]bool {
	s := make(map[RuntimeMode]bool, len(tmpl.RuntimeSupport.Supported))
	for _, m := range tmpl.RuntimeSupport.Supported {
		s[RuntimeMode(m)] = true
	}
	return s
}

// shapeFor returns the credential delivery shape for a given runtime mode.
// If a new RuntimeMode is added to AllModes but not to this switch, the panic
// surfaces the omission at test time (S-2 matrix tests exercise all modes).
func shapeFor(m RuntimeMode) CredentialDelivery {
	switch m {
	case RuntimeGatewayTyped, RuntimeGatewaySDK, RuntimeGatewayProxy:
		return DeliveryKeylatchSessionToken
	case RuntimeDirectBrokered:
		return DeliveryProviderEphemeral
	case RuntimeDirectClassicSandboxed:
		// Sandboxed mode injects credentials directly but inside an OS
		// sandbox (bwrap/sandbox-exec). Delivery shape is provider_root because
		// the raw credential is injected into the sandboxed env, not brokered.
		return DeliveryProviderRoot
	default:
		panic(fmt.Sprintf("runtime: shapeFor: unrecognized mode %q — update shapeFor when adding to AllModes", m))
	}
}
