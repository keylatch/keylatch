package runner

import (
	"net/url"

	"github.com/keylatch/keylatch/internal/registry"
)

// AdapterPortPlaceholder stands in for the port of the adapter's loopback
// listener until the process that starts the child fills it in.
const AdapterPortPlaceholder = "{adapter-port}"

// DockerConfigPlaceholder stands in for the directory of the Docker client
// configuration that names the Keylatch credential store, until the process
// that starts the child creates it.
const DockerConfigPlaceholder = "{docker-config}"

// DockerCredentialEnv returns the child environment changes that make the
// Docker client ask keylatch for registry credentials, for templates whose
// adapter is the Docker credential store. The helper answers with a
// placeholder for the registries the adapter names and with nothing for any
// other.
func DockerCredentialEnv(tmpl registry.ConnectionTemplate, sessionID string) []EnvAssign {
	if tmpl.Adapter.Kind != registry.AdapterDockerCredential {
		return nil
	}
	return []EnvAssign{
		{"DOCKER_CONFIG", DockerConfigPlaceholder},
		{ProxySessionVar, sessionID},
	}
}

// pgVars are the libpq variables an adapter run sets or clears, so a database
// the caller's environment names is never reached around the adapter.
var pgVars = []string{
	"PGHOST", "PGHOSTADDR", "PGPORT", "PGUSER", "PGPASSWORD", "PGPASSFILE", "PGSERVICE", "PGSERVICEFILE",
	"PGDATABASE", "PGSSLMODE", "PGSSLROOTCERT", "PGSSLCERT", "PGSSLKEY", "PGOPTIONS", "DATABASE_URL",
}

// PostgresAdapterEnv returns the child environment changes for a run through
// the Postgres adapter. The child gets the adapter's loopback address, a role
// name and the session token as its password; the real password is neither
// here nor anywhere the child can read. The variables the template would have
// put the real value in are cleared.
func PostgresAdapterEnv(tmpl registry.ConnectionTemplate, user, database, token string) SessionEnv {
	env := SessionEnv{Strip: append([]string(nil), pgVars...)}
	for _, rule := range tmpl.InjectionRules {
		env.Strip = append(env.Strip, rule.EnvVar)
	}
	if database == "" {
		database = "postgres"
	}
	// Built by hand: url.URL would escape the braces of the port placeholder.
	dsn := "postgresql://" + url.UserPassword(user, token).String() + "@127.0.0.1:" + AdapterPortPlaceholder + "/" + url.PathEscape(database) + "?sslmode=disable"
	env.Set = []EnvAssign{
		{"PGHOST", "127.0.0.1"},
		{"PGPORT", AdapterPortPlaceholder},
		{"PGUSER", user},
		{"PGPASSWORD", token},
		{"PGDATABASE", database},
		{"PGSSLMODE", "disable"},
		{"DATABASE_URL", dsn},
		{"KEYLATCH_RUNTIME", "adapter"},
	}
	return env
}
