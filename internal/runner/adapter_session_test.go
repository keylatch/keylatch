package runner

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keylatch/keylatch/internal/registry"
)

func TestPostgresAdapterEnvHoldsTheTokenAndClearsAmbientDatabaseSettings(t *testing.T) {
	tmpl := registry.ConnectionTemplate{InjectionRules: []registry.InjectionRule{{EnvVar: "SUPABASE_DB_PASSWORD", Source: "db_password"}}}
	env := PostgresAdapterEnv(tmpl, "app owner", "my db", "klph_token")

	set := map[string]string{}
	for _, e := range env.Set {
		set[e.Name] = e.Value
	}
	assert.Equal(t, "127.0.0.1", set["PGHOST"])
	assert.Equal(t, AdapterPortPlaceholder, set["PGPORT"])
	assert.Equal(t, "app owner", set["PGUSER"])
	assert.Equal(t, "klph_token", set["PGPASSWORD"])
	assert.Equal(t, "my db", set["PGDATABASE"])
	assert.Equal(t, "disable", set["PGSSLMODE"])
	assert.Equal(t, "postgresql://app%20owner:klph_token@127.0.0.1:"+AdapterPortPlaceholder+"/my%20db?sslmode=disable", set["DATABASE_URL"])
	assert.Equal(t, "adapter", set["KEYLATCH_RUNTIME"])
	for _, v := range []string{"PGHOSTADDR", "PGPASSFILE", "PGSERVICE", "PGSSLROOTCERT", "SUPABASE_DB_PASSWORD"} {
		assert.Contains(t, env.Strip, v)
	}

	base := []string{"PGHOST=db.internal", "PGPASSFILE=/home/u/.pgpass", "SUPABASE_DB_PASSWORD=hunter2", "PATH=/usr/bin"}
	got := strings.Join(env.Apply(base, false, nil), "\n")
	assert.NotContains(t, got, "db.internal")
	assert.NotContains(t, got, "pgpass")
	assert.NotContains(t, got, "hunter2")
	assert.Contains(t, got, "PGPASSWORD=klph_token")

	assert.Equal(t, "postgres", func() string {
		for _, e := range PostgresAdapterEnv(tmpl, "u", "", "t").Set {
			if e.Name == "PGDATABASE" {
				return e.Value
			}
		}
		return ""
	}(), "the database defaults to postgres")
}

func TestDockerCredentialEnvOnlyForTheDockerAdapter(t *testing.T) {
	assert.Nil(t, DockerCredentialEnv(registry.ConnectionTemplate{Adapter: registry.Adapter{Kind: registry.AdapterGitCredential}}, "s"))
	got := DockerCredentialEnv(registry.ConnectionTemplate{Adapter: registry.Adapter{Kind: registry.AdapterDockerCredential}}, "sess")
	require.Len(t, got, 2)
	assert.Equal(t, EnvAssign{"DOCKER_CONFIG", DockerConfigPlaceholder}, got[0])
	assert.Equal(t, EnvAssign{ProxySessionVar, "sess"}, got[1])
}
