package ci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/keylatch/keylatch/internal/config"
)

// SessionEnv names the environment variable that points later steps of a job at
// the session record an exchange wrote.
const SessionEnv = "KEYLATCH_CI_SESSION"

const (
	sessionFile    = "keylatch-ci-session.json"
	defaultTTL     = time.Hour
	tokenBodyLimit = 1 << 16
)

// Session is what an exchange grants: the connections one verified job may
// use until Expires. It holds no secret; it narrows what Keylatch allows.
type Session struct {
	Provider    string    `json:"provider"`
	Repository  string    `json:"repository"`
	Ref         string    `json:"ref"`
	Environment string    `json:"environment,omitempty"`
	Connections []string  `json:"connections"`
	Expires     time.Time `json:"expires"`
}

// NewSession builds the session an accepted token earns under trust, ending at
// the earliest of the token's expiry and the trust entry's lifetime.
func NewSession(id Identity, trust config.CITrust, now time.Time) Session {
	ttl := defaultTTL
	if trust.MaxTTL > 0 {
		ttl = time.Duration(trust.MaxTTL) * time.Second
	}
	expires := now.Add(ttl)
	if !id.Expiry.IsZero() && id.Expiry.Before(expires) {
		expires = id.Expiry
	}
	return Session{
		Provider: id.Provider, Repository: id.Repository, Ref: id.Ref, Environment: id.Environment,
		Connections: slices.Clone(trust.Connections), Expires: expires.UTC(),
	}
}

// Allows reports whether the session covers connection at now.
func (s Session) Allows(connection string, now time.Time) bool {
	return now.Before(s.Expires) && slices.Contains(s.Connections, connection)
}

// WriteSession stores s as a private file in dir and returns its path.
func WriteSession(dir string, s Session) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, sessionFile)
	tmp, err := os.CreateTemp(dir, ".ci-session-*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// ReadSession loads a session record. A record that cannot be read or has no
// connection is an error so callers can fail closed.
func ReadSession(path string) (Session, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Session{}, err
	}
	var s Session
	if err := json.Unmarshal(data, &s); err != nil {
		return Session{}, fmt.Errorf("ci: session record %q is damaged: %w", path, err)
	}
	if len(s.Connections) == 0 || s.Expires.IsZero() {
		return Session{}, fmt.Errorf("ci: session record %q is incomplete", path)
	}
	return s, nil
}

// SessionDir is where a job's session record goes: the runner's private temp
// directory when there is one.
func SessionDir(getenv func(string) string) string {
	for _, name := range []string{"RUNNER_TEMP", "CI_BUILDS_DIR"} {
		if d := getenv(name); d != "" {
			return filepath.Join(d, "keylatch")
		}
	}
	return filepath.Join(os.TempDir(), "keylatch-ci")
}

// ExportEnv appends KEY=value to the file a CI system reads between steps
// (GITHUB_ENV, or a dotenv artifact on GitLab).
func ExportEnv(file, key, value string) error {
	if strings.ContainsAny(key+value, "\r\n") {
		return errors.New("ci: refusing to export a multi-line value")
	}
	f, err := os.OpenFile(file, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s=%s\n", key, value); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// GitHubToken asks the Actions runner for an ID token with the given audience.
func GitHubToken(ctx context.Context, client *http.Client, getenv func(string) string, audience string) (string, error) {
	base, bearer := getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if base == "" || bearer == "" {
		return "", errors.New("ci: the job cannot request an OIDC token; grant it `permissions: id-token: write`")
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("ci: ACTIONS_ID_TOKEN_REQUEST_URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if client == nil {
		client = &http.Client{Timeout: jwksFetchTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("ci: request OIDC token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ci: the runner refused the OIDC token request (%s)", resp.Status)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, tokenBodyLimit)).Decode(&body); err != nil || body.Value == "" {
		return "", errors.New("ci: the runner returned no OIDC token")
	}
	return body.Value, nil
}
