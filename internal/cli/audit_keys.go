package cli

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/keylatch/keylatch/internal/audit"
	"github.com/keylatch/keylatch/internal/callerkind"
	"github.com/keylatch/keylatch/internal/config"
	"github.com/keylatch/keylatch/internal/crypto/kek"
	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
)

// auditKeys is the key material the audit log needs: the DEK new events are
// sealed with, the DEKs of earlier terms, and the seed the chain MAC key comes
// from.
type auditKeys struct {
	dek   []byte
	older [][]byte
	seed  []byte
}

func (k *auditKeys) zero() {
	clear(k.dek)
	clear(k.seed)
	for _, o := range k.older {
		clear(o)
	}
}

// loadAuditKeyMaterial opens the keyring once and derives everything the audit
// log needs. The chain seed comes from a secret wrapped by the KEK, so it
// cannot be recomputed from the audit salt, which is a readable file. With
// create set a missing secret is generated, and a log written under the
// previous (salt-only) key is moved aside so the new chain starts clean.
func loadAuditKeyMaterial(salt []byte, create bool) (*auditKeys, error) {
	dek, older, k, err := loadAuditKeysWithKEK()
	if err != nil {
		return nil, err
	}
	keys := &auditKeys{dek: dek, older: older}

	keyPath := paths.AuditKeyWrapped(os.Getenv)
	_, statErr := os.Stat(keyPath)
	fresh := errors.Is(statErr, os.ErrNotExist)
	secret, err := kek.LoadOrCreateSecret(keyPath, k, create)
	if err != nil {
		keys.zero()
		if errors.Is(err, kek.ErrSecretMissing) {
			return nil, fmt.Errorf("audit key %q does not exist: open the audit log once with a command that records events", keyPath)
		}
		return nil, fmt.Errorf("audit key: %w", err)
	}
	defer clear(secret)
	if fresh {
		if err := audit.RetireLog(paths.Audit(os.Getenv), auditRetainFiles()); err != nil {
			keys.zero()
			return nil, err
		}
	}
	keys.seed = audit.ChainSeed(secret, salt)
	return keys, nil
}

// callerKindOfProcess is the caller kind recorded for commands run in this
// process: an agent when the process shows LLM-session signals.
func callerKindOfProcess() string {
	if llmcontext.IsLLMSession(llmcontext.DefaultLookup) {
		return string(callerkind.Agent)
	}
	return string(callerkind.Human)
}

// loadAuditKeysWithKEK returns the DEK new audit events are sealed with, the
// older DEKs earlier events may be sealed with (retired terms of the same
// keyring and, where an install still has the legacy keyring beside the
// bootstrap one, that keyring's DEKs) and the KEK that opened the keyring.
func loadAuditKeysWithKEK() ([]byte, [][]byte, kek.KEK, error) {
	// An LLM session never gets a passphrase prompt.
	kr, k, krPath, err := openKeyringAt(paths.ResolveKeyringPath(os.Getenv), callerKindOfProcess() == string(callerkind.Human))
	if err != nil {
		return nil, nil, nil, err
	}
	defer kr.Zero()
	dek, term, err := kr.ActiveDEK()
	if err != nil {
		return nil, nil, nil, err
	}
	active := bytes.Clone(dek)
	older := retiredDEKs(kr, term)

	if legacy := paths.LegacyKeyringPath(os.Getenv); legacy != krPath {
		if _, statErr := os.Stat(legacy); statErr == nil {
			if lkr, _, _, openErr := openKeyringAt(legacy, false); openErr == nil {
				if ldek, lterm, dekErr := lkr.ActiveDEK(); dekErr == nil {
					older = append(older, bytes.Clone(ldek))
					older = append(older, retiredDEKs(lkr, lterm)...)
				}
				lkr.Zero()
			}
		}
	}
	return active, older, k, nil
}

// auditRetainFiles is how many rotated log files the configuration keeps.
func auditRetainFiles() int {
	cfg, err := config.Load(paths.Config(llmcontext.DefaultLookup))
	if err != nil {
		return audit.DefaultRetainFiles
	}
	return audit.LoadRetainFiles(cfg.Audit)
}
