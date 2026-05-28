// Package keyring migration support for Phase 11.
// Handles upgrading schema version 1 (Phase 5) keyrings to schema version 2.
package keyring

import (
	"encoding/base64"
	"fmt"

	"github.com/keylatch/keylatch/internal/trust"
)

// migrateV1toV2 synthesises a Phase 11 Roots slice from the legacy KEK fields
// if the keyring was loaded as schema version 1.
//
// The migration does NOT write the keyring to disk — the caller is responsible
// for persisting the updated file when desired.
//
// Algorithm:
//  1. If kf.Roots is already non-empty, return unchanged (idempotent).
//  2. If legacy KEKType is empty, return an error (corrupt legacy keyring).
//  3. Map KEKType → trust.RootType.
//  4. Build a RootSpec with Status=RootActive.
//  5. Copy each term's WrappedDEK (base64-encoded) into WrappedDEKs map.
//  6. Set kf.SchemaVersion = 2.
func migrateV1toV2(kf *KeyringFile) error { //nolint:unused // planned: called from keyring.Open when SchemaVersion < 2 detected
	// Idempotent: already migrated.
	if len(kf.Roots) > 0 {
		return nil
	}

	if kf.KEKType == "" {
		return fmt.Errorf("%w: legacy keyring missing kek_type", ErrKeyringCorrupt)
	}

	rootType := legacyKEKTypeToRootType(kf.KEKType)
	kekID := kf.KEKID
	if kekID == "" {
		kekID = kf.KEKType // fallback: use type as ID if KEKID was not set
	}

	spec := trust.RootSpec{
		ID:     kekID,
		Type:   rootType,
		Status: trust.RootActive,
		Label:  "migrated-" + kf.KEKType,
	}

	// Build wrapped DEK map from legacy terms.
	wrappedDEKs := make(map[int]string)
	for _, term := range kf.Terms {
		if len(term.WrappedDEK) > 0 {
			wrappedDEKs[term.Term] = base64.StdEncoding.EncodeToString(term.WrappedDEK)
		}
	}

	kf.Roots = []RootOfTrustRecord{
		{
			Spec:        spec,
			WrappedDEKs: wrappedDEKs,
		},
	}
	kf.SchemaVersion = SchemaVersion
	return nil
}

// legacyKEKTypeToRootType maps Phase 5 KEKType strings to Phase 11 RootType values.
//
//nolint:unused // called from migrateV1toV2 (which is itself planned)
func legacyKEKTypeToRootType(kekType string) trust.RootType {
	return LegacyKEKTypeToRootType(kekType)
}

// LegacyKEKTypeToRootType is the exported version of the legacy KEK type conversion.
// Use this from CLI and other packages to avoid duplicating the mapping.
func LegacyKEKTypeToRootType(kekType string) trust.RootType {
	switch kekType {
	case "passphrase":
		return trust.RootPassphrase
	case "keychain":
		return trust.RootKeychain
	case "op":
		return trust.RootOnePassword
	case "bw":
		return trust.RootBitwarden
	case "age-env":
		return trust.RootEncryptedFile
	default:
		return trust.RootType(kekType)
	}
}
