package cli

// guard_approval_root.go — hardware approval JWT validation
// for direct_classic_sandboxed runtime mode.
//
// Security invariants:
//   - Approval root IDs in the JWT are HMAC'd; they are never raw.
//   - GuardRuntime calls ValidateApprovalRootJWT when a 32-byte signing key is
//     provided. Without a signing key, GuardRuntime blocks any approval JWT.
//   - ValidateApprovalRootJWT performs full cryptographic validation (HS256 sig,
//     expiry, and presence of hardware root claims).

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ApprovalRootClaims holds the approval root fields from a gateway JWT.
// All root IDs are HMAC'd.
type ApprovalRootClaims struct {
	// ApprovalRootHMAC is the HMAC of the primary approval root spec ID.
	ApprovalRootHMAC string
	// ApprovalCapability is the capability the approval covers.
	ApprovalCapability string
	// ApprovalMaxAgeSec is the maximum accepted presence proof age.
	ApprovalMaxAgeSec int
	// ApprovalExpiry is the hardware approval expiry time.
	ApprovalExpiry time.Time
	// ApprovalBinding is the challenge binding mode.
	ApprovalBinding string
	// TwoPerson is true when two distinct hardware approvals were required.
	TwoPerson bool
	// ApprovalRootHMACs holds all HMAC'd root IDs (two-person use).
	ApprovalRootHMACs []string
}

// ErrApprovalJWTInvalid is returned when the approval JWT fails validation.
var ErrApprovalJWTInvalid = errors.New("approval JWT invalid or expired")

// ErrApprovalJWTMissingRootClaims is returned when the JWT lacks approval root claims.
var ErrApprovalJWTMissingRootClaims = errors.New("approval JWT missing hardware root claims")

// ErrApprovalExpired is returned when the hardware approval has expired (independent of JWT exp).
var ErrApprovalExpired = errors.New("approval JWT: hardware approval has expired")

// approvalJWTClaims is the shape of the gateway JWT claims we extract approval root data from.
type approvalJWTClaims struct {
	jwt.RegisteredClaims
	ApprovalRootHMAC  string   `json:"apv_root_hmac"`
	ApprovalCap       string   `json:"apv_cap"`
	ApprovalMaxAgeSec int      `json:"apv_max_age_sec"`
	ApprovalExpiry    string   `json:"apv_exp"`
	ApprovalBinding   string   `json:"apv_binding"`
	TwoPerson         bool     `json:"apv_two_person"`
	ApprovalRootHMACs []string `json:"apv_root_hmacs"`
}

// ValidateApprovalRootJWT parses and validates an approval JWT for
// direct_classic_sandboxed mode (E14 T3).
//
// It verifies:
//  1. JWT signature and expiry using signingKey.
//  2. The JWT contains non-empty apv_root_hmac (hardware root was used).
//  3. The hardware approval has not expired (apv_exp, if set).
//  4. If requireTwoPerson is true, apv_two_person must be set and
//     apv_root_hmacs must have at least 2 entries.
//
// Returns the extracted ApprovalRootClaims on success.
// Returns ErrApprovalJWTInvalid when the JWT is malformed or signature fails.
// Returns ErrApprovalJWTMissingRootClaims when hardware approval claims are absent.
// Returns ErrApprovalExpired when the hardware approval time has passed.
func ValidateApprovalRootJWT(jwtStr string, signingKey []byte, requireTwoPerson bool) (ApprovalRootClaims, error) {
	if len(signingKey) != 32 {
		return ApprovalRootClaims{}, fmt.Errorf("%w: signing key must be 32 bytes", ErrApprovalJWTInvalid)
	}

	claims := &approvalJWTClaims{}
	parsed, err := jwt.ParseWithClaims(jwtStr, claims, func(_ *jwt.Token) (interface{}, error) {
		return signingKey, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		return ApprovalRootClaims{}, fmt.Errorf("%w: %v", ErrApprovalJWTInvalid, err)
	}
	if !parsed.Valid {
		return ApprovalRootClaims{}, ErrApprovalJWTInvalid
	}

	// Require hardware root HMAC (must be HMAC'd, not raw).
	if claims.ApprovalRootHMAC == "" {
		return ApprovalRootClaims{}, ErrApprovalJWTMissingRootClaims
	}

	// Parse and check hardware approval expiry (independent of JWT exp).
	var approvalExpiry time.Time
	if claims.ApprovalExpiry != "" {
		approvalExpiry, err = time.Parse(time.RFC3339, claims.ApprovalExpiry)
		if err != nil {
			return ApprovalRootClaims{}, fmt.Errorf("%w: parse apv_exp: %v", ErrApprovalJWTInvalid, err)
		}
		if time.Now().UTC().After(approvalExpiry) {
			return ApprovalRootClaims{}, ErrApprovalExpired
		}
	}

	// Two-person check.
	if requireTwoPerson {
		if !claims.TwoPerson {
			return ApprovalRootClaims{}, fmt.Errorf("%w: two-person approval required but not present", ErrApprovalJWTMissingRootClaims)
		}
		if len(claims.ApprovalRootHMACs) < 2 {
			return ApprovalRootClaims{}, fmt.Errorf("%w: two-person approval requires >= 2 root HMACs, got %d",
				ErrApprovalJWTMissingRootClaims, len(claims.ApprovalRootHMACs))
		}
	}

	return ApprovalRootClaims{
		ApprovalRootHMAC:   claims.ApprovalRootHMAC,
		ApprovalCapability: claims.ApprovalCap,
		ApprovalMaxAgeSec:  claims.ApprovalMaxAgeSec,
		ApprovalExpiry:     approvalExpiry,
		ApprovalBinding:    claims.ApprovalBinding,
		TwoPerson:          claims.TwoPerson,
		ApprovalRootHMACs:  claims.ApprovalRootHMACs,
	}, nil
}
