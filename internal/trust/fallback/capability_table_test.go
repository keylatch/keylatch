package fallback

import (
	"testing"

	"github.com/keylatch/keylatch/internal/trust"
)

func TestCapabilityFromName(t *testing.T) {
	cases := map[string]trust.Capability{
		"wrap":             trust.CapWrap,
		"WRAP":             trust.CapWrap,
		"sign":             trust.CapSignChallenge,
		"sign_challenge":   trust.CapSignChallenge,
		"user_presence":    trust.CapUserPresence,
		"hardware_bound":   trust.CapHardwareBound,
		"launchd_safe":     trust.CapLaunchdSafe,
		"attestation":      trust.CapAttestation,
		"mtls_client_auth": trust.CapMTLSClientAuth,
		"":                 0,
		"teleport":         0,
	}
	for name, want := range cases {
		if got := capabilityFromName(name); got != want {
			t.Errorf("capabilityFromName(%q) = %d, want %d", name, got, want)
		}
	}
}

func TestTypeHasCapabilityTable(t *testing.T) {
	cases := []struct {
		rt   trust.RootType
		c    trust.Capability
		want bool
	}{
		{trust.RootPassphrase, trust.CapWrap, true},
		{trust.RootPassphrase, trust.CapSignChallenge, false},
		{trust.RootEncryptedFile, trust.CapSignChallenge, false},
		{trust.RootBitwarden, trust.CapSignChallenge, false},
		{trust.RootOnePassword, trust.CapSignChallenge, false},
		{trust.RootSSHAgent, trust.CapSignChallenge, true},
		{trust.RootSecureEnclave, trust.CapUserPresence, true},
		{trust.RootFIDO2, trust.CapUserPresence, true},
		{trust.RootGPGCard, trust.CapUserPresence, true},
		{trust.RootSSHAgent, trust.CapUserPresence, false},
		{trust.RootPKCS11, trust.CapUserPresence, false},
		{trust.RootSecureEnclave, trust.CapHardwareBound, true},
		{trust.RootFIDO2, trust.CapHardwareBound, true},
		{trust.RootPKCS11, trust.CapHardwareBound, true},
		{trust.RootVaultTransit, trust.CapHardwareBound, false},
		{trust.RootVaultTransit, trust.CapAttestation, true},
	}
	for _, tc := range cases {
		if got := typeHasCapability(tc.rt, tc.c); got != tc.want {
			t.Errorf("typeHasCapability(%s, %d) = %v, want %v", tc.rt, tc.c, got, tc.want)
		}
	}
}

func TestPresenceAndLaunchdTables(t *testing.T) {
	for _, rt := range []trust.RootType{trust.RootSecureEnclave, trust.RootFIDO2, trust.RootGPGCard} {
		if !requiresPresence(rt) || !knownNonLaunchdSafe(rt) {
			t.Errorf("%s should require presence and be launchd-unsafe", rt)
		}
	}
	for _, rt := range []trust.RootType{trust.RootPassphrase, trust.RootSSHAgent, trust.RootPKCS11, trust.RootVaultTransit} {
		if requiresPresence(rt) || knownNonLaunchdSafe(rt) {
			t.Errorf("%s should not be pre-screened", rt)
		}
	}
}
