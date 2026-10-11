package grant

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mxResetAccessorKey clears the process-wide accessor key cache so a test can
// observe loadOrCreateAccessorKey against its own paths, and restores a clean
// cache afterwards so later tests are unaffected.
func mxResetAccessorKey(t *testing.T) {
	t.Helper()
	reset := func() {
		accessorKeyOnce = sync.Once{}
		accessorKey = nil
		accessorKeyErr = nil
	}
	reset()
	t.Cleanup(reset)
}

func mxEnv(dir string, overrides map[string]string) func(string) string {
	return func(k string) string {
		if v, ok := overrides[k]; ok {
			return v
		}
		switch k {
		case "KEYLATCH_CONFIG_DIR":
			return dir
		case "KEYLATCH_GRANTS_PATH":
			return filepath.Join(dir, "grants.json")
		case "KEYLATCH_GRANTS_DIR":
			return filepath.Join(dir, "grants")
		case "KEYLATCH_GRANT_ACCESSOR_KEY_PATH":
			return filepath.Join(dir, "grant-accessor.key")
		}
		return ""
	}
}

func mxBlockingFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "plain-file")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o600))
	return p
}

func TestNewUUID_IsV4(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := newUUID()
		require.NoError(t, err)
		assert.Regexp(t, re, id)
		assert.False(t, seen[id])
		seen[id] = true
	}
}

func TestAccessorKey_ReusesExistingKey(t *testing.T) {
	mxResetAccessorKey(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "grant-accessor.key")
	existing := bytes.Repeat([]byte{7}, 32)
	require.NoError(t, os.WriteFile(keyPath, existing, 0o600))

	key, err := loadOrCreateAccessorKey(mxEnv(dir, nil))
	require.NoError(t, err)
	assert.Equal(t, existing, key)

	g, err := Create(context.Background(), GrantSpec{Actor: "a", Connection: "c", Capability: "inject"}, mxEnv(dir, nil))
	require.NoError(t, err)
	assert.Equal(t, computeAccessor(g.ID, existing), g.Accessor, "accessor is an HMAC of the id under the stored key")
	assert.NotEqual(t, g.ID, g.Accessor)
}

func TestAccessorKey_ReplacesWrongLengthKey(t *testing.T) {
	mxResetAccessorKey(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "grant-accessor.key")
	require.NoError(t, os.WriteFile(keyPath, []byte("short"), 0o644))

	key, err := loadOrCreateAccessorKey(mxEnv(dir, nil))
	require.NoError(t, err)
	assert.Len(t, key, 32)
	onDisk, err := os.ReadFile(keyPath) //nolint:gosec // temp path
	require.NoError(t, err)
	assert.Equal(t, key, onDisk)
	if runtime.GOOS != "windows" {
		info, err := os.Stat(keyPath)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestAccessorKey_FailuresSurfaceFromCreate(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"parent is a file": func(t *testing.T) string { return filepath.Join(mxBlockingFile(t), "key") },
		"path is a dir":    func(t *testing.T) string { return t.TempDir() },
	}
	for name, keyPath := range cases {
		t.Run(name, func(t *testing.T) {
			mxResetAccessorKey(t)
			dir := t.TempDir()
			env := mxEnv(dir, map[string]string{"KEYLATCH_GRANT_ACCESSOR_KEY_PATH": keyPath(t)})
			_, err := Create(context.Background(), GrantSpec{Actor: "a"}, env)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "accessor key")
			_, statErr := os.Stat(filepath.Join(dir, "grants.json"))
			assert.True(t, os.IsNotExist(statErr), "no grant may be persisted without an accessor key")
		})
	}
}

func TestCreate_StorageFailures(t *testing.T) {
	dir := t.TempDir()
	corrupt := filepath.Join(dir, "corrupt.json")
	require.NoError(t, os.WriteFile(corrupt, []byte("{not an array"), 0o600))

	_, err := Create(context.Background(), GrantSpec{Actor: "a"}, mxEnv(dir, map[string]string{"KEYLATCH_GRANTS_PATH": corrupt}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse")

	_, err = Create(context.Background(), GrantSpec{Actor: "a", MaxUses: 1}, mxEnv(dir, map[string]string{"KEYLATCH_GRANTS_DIR": filepath.Join(mxBlockingFile(t), "sub")}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir grants dir")

	_, err = Create(context.Background(), GrantSpec{Actor: "a"}, mxEnv(dir, map[string]string{"KEYLATCH_GRANTS_PATH": filepath.Join(mxBlockingFile(t), "grants.json")}))
	require.Error(t, err)
}

func TestCreate_DefaultTTLIsOneHour(t *testing.T) {
	g, err := Create(context.Background(), GrantSpec{Actor: "a"}, mxEnv(t.TempDir(), nil))
	require.NoError(t, err)
	assert.Equal(t, time.Hour, g.ExpiresAt.Sub(g.IssuedAt))
	assert.Empty(t, g.ConsumptionLogPath, "unlimited grants need no consumption log")
}

func TestReadWriteGrants_Errors(t *testing.T) {
	gs, err := readGrants(filepath.Join(t.TempDir(), "absent.json"))
	require.NoError(t, err)
	assert.Nil(t, gs)

	_, err = readGrants(t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "grant: read")

	err = writeGrants(filepath.Join(mxBlockingFile(t), "grants.json"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mkdir")

	// Target is a non-empty directory: rename fails and the temp file is removed.
	dir := t.TempDir()
	target := filepath.Join(dir, "grants.json")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "occupied"), 0o700))
	err = writeGrants(target, []Grant{{ID: "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rename")
	_, statErr := os.Stat(target + ".tmp")
	assert.True(t, os.IsNotExist(statErr))

	err = writeGrants(filepath.Join(t.TempDir(), "sub", "grants.json"), []Grant{{ID: "y"}})
	require.NoError(t, err)
}

func TestListRevokeFind_CorruptFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grants.json")
	require.NoError(t, os.WriteFile(p, []byte("garbage"), 0o600))

	_, err := List(context.Background(), p, ListOpts{})
	assert.Error(t, err)
	assert.Error(t, Revoke(context.Background(), p, "id"))
	g, ok := Find(context.Background(), p, FindRequest{Actor: "a"})
	assert.False(t, ok, "an unreadable grant store must fail closed")
	assert.Nil(t, g)
}

func TestList_Filters(t *testing.T) {
	p := filepath.Join(t.TempDir(), "grants.json")
	now := time.Now().UTC()
	require.NoError(t, writeGrants(p, []Grant{
		{ID: "live-a", Actor: "alice", ExpiresAt: now.Add(time.Hour)},
		{ID: "live-b", Actor: "bob", ExpiresAt: now.Add(time.Hour)},
		{ID: "expired", Actor: "alice", ExpiresAt: now.Add(-time.Hour)},
		{ID: "revoked", Actor: "alice", ExpiresAt: now.Add(time.Hour), Revoked: true},
	}))
	ids := func(opts ListOpts) []string {
		gs, err := List(context.Background(), p, opts)
		require.NoError(t, err)
		out := []string{}
		for _, g := range gs {
			out = append(out, g.ID)
		}
		return out
	}
	assert.Equal(t, []string{"live-a", "live-b"}, ids(ListOpts{}))
	assert.Equal(t, []string{"live-a"}, ids(ListOpts{ActorFilter: "alice"}))
	assert.Equal(t, []string{"live-a", "expired", "revoked"}, ids(ListOpts{ActorFilter: "alice", IncludeExpired: true, IncludeRevoked: true}))
}

func TestGrantFieldsMatch(t *testing.T) {
	g := &Grant{Actor: "alice", Connection: "openai", Capability: "inject"}
	assert.True(t, grantFieldsMatch(g, FindRequest{Actor: "alice", Connection: "openai", Capability: "inject"}))
	assert.False(t, grantFieldsMatch(g, FindRequest{}), "an empty request field never satisfies a grant that names one")
	assert.False(t, grantFieldsMatch(g, FindRequest{Actor: "mallory"}))
	assert.False(t, grantFieldsMatch(g, FindRequest{Connection: "anthropic"}))
	assert.False(t, grantFieldsMatch(g, FindRequest{Capability: "read"}))
	assert.True(t, grantFieldsMatch(&Grant{}, FindRequest{Actor: "x", Connection: "y", Capability: "z"}), "empty grant fields act as wildcards")
}

func TestConsumeUse_LegacyCounter(t *testing.T) {
	g := &Grant{MaxUses: 2, UsesRemaining: 2}
	assert.True(t, consumeUse(g))
	assert.True(t, consumeUse(g))
	assert.False(t, consumeUse(g), "legacy counter must stop at zero")
	assert.Equal(t, 0, g.UsesRemaining)
}

func TestFind_MaxUsesExhaustsAcrossCalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock path covered on unix")
	}
	env := mxEnv(t.TempDir(), nil)
	g, err := Create(context.Background(), GrantSpec{Actor: "a", Connection: "c", Capability: "inject", MaxUses: 2}, env)
	require.NoError(t, err)
	require.NotEmpty(t, g.ConsumptionLogPath)

	path := env("KEYLATCH_GRANTS_PATH")
	req := FindRequest{Actor: "a", Connection: "c", Capability: "inject"}
	for i := 0; i < 2; i++ {
		_, ok := Find(context.Background(), path, req)
		require.True(t, ok, "use %d", i+1)
	}
	_, ok := Find(context.Background(), path, req)
	assert.False(t, ok, "third use exceeds MaxUses")
	n, err := countLines(g.ConsumptionLogPath)
	require.NoError(t, err)
	assert.Equal(t, 2, n)
}

func TestConsumeUseLog_FailsClosedOnFilesystemErrors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("flock path covered on unix")
	}
	g := &Grant{ID: "g", MaxUses: 5, ConsumptionLogPath: filepath.Join(mxBlockingFile(t), "c.log")}
	assert.False(t, consumeUseLog(g), "unreachable log dir must not grant a use")

	dir := t.TempDir()
	logPath := filepath.Join(dir, "c.log")
	require.NoError(t, os.MkdirAll(logPath+".lock", 0o700))
	g = &Grant{ID: "g", MaxUses: 5, ConsumptionLogPath: logPath}
	assert.False(t, consumeUseLog(g), "lock file that cannot be opened must not grant a use")

	dir = t.TempDir()
	logPath = filepath.Join(dir, "c.log")
	require.NoError(t, os.MkdirAll(logPath, 0o700))
	g = &Grant{ID: "g", MaxUses: 5, ConsumptionLogPath: logPath}
	assert.False(t, consumeUseLog(g), "unreadable log must not grant a use")
}
