package approval

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keylatch/keylatch/internal/crypto/argon2"
)

var (
	testKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	testPub = testKey.Public().(ed25519.PublicKey)
)

// cheapKDF keeps approver key derivation fast under -race.
var cheapKDF = argon2.Params{Time: 1, Memory: 1024, Threads: 1, KeyLen: 32}

// tok returns a valid approval token derived from a readable test name.
func tok(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "apv_" + hex.EncodeToString(sum[:16])
}

func readApprovalFile(path string) (*ApprovalRequest, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readApproval(root, strings.TrimSuffix(filepath.Base(path), ".json"))
}

func writeApprovalFile(path string, ar *ApprovalRequest) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer root.Close()
	return writeApproval(root, ar)
}

func mustWrite(t *testing.T, dir string, ar *ApprovalRequest) {
	t.Helper()
	if err := writeApprovalFile(filepath.Join(dir, ar.Token+".json"), ar); err != nil {
		t.Fatalf("writeApproval: %v", err)
	}
}
