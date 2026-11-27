package canary

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

// Honey is a decoy credential file for a sandbox's home directory. Its
// content looks like what the tool it imitates writes, so a hostile command
// that collects credentials takes it.
type Honey struct {
	// Path is relative to the home directory.
	Path    string
	Content string
}

// Set is the decoys of one session: an environment variable and a few files.
// Every value is unique to the session, worthless, and recorded nowhere but
// here, so seeing one in a request means the command sent a credential it was
// never given.
type Set struct {
	Env    map[string]string
	Files  []Honey
	Values []string
}

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	base64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
)

func random(alphabet string, n int) (string, error) {
	var b strings.Builder
	limit := big.NewInt(int64(len(alphabet)))
	for range n {
		i, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("canary: random source: %w", err)
		}
		b.WriteByte(alphabet[i.Int64()])
	}
	return b.String(), nil
}

// NewSet returns the decoys for a session on the given provider.
func NewSet(provider string) (Set, error) {
	token, err := BuildCanary(provider)
	if err != nil {
		return Set{}, err
	}
	pieces := map[string]struct {
		alphabet string
		n        int
	}{"akia": {upper, 16}, "aws": {base64, 40}, "gh": {alnum, 36}, "npm": {alnum, 36}}
	got := map[string]string{}
	for name, p := range pieces {
		if got[name], err = random(p.alphabet, p.n); err != nil {
			return Set{}, err
		}
	}
	// The prefixes are split so source scanners do not take them for keys.
	akia, aws, gh, npm := "AK"+"IA"+got["akia"], got["aws"], "gh"+"p_"+got["gh"], "np"+"m_"+got["npm"]
	return Set{
		Env: map[string]string{EnvVarName(provider): token},
		Files: []Honey{
			{Path: ".aws/credentials", Content: fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", akia, aws)},
			{Path: ".config/gh/hosts.yml", Content: fmt.Sprintf("github.com:\n    oauth_token: %s\n    user: ci\n    git_protocol: https\n", gh)},
			{Path: ".npmrc", Content: fmt.Sprintf("//registry.npmjs.org/:_authToken=%s\n", npm)},
		},
		Values: []string{token, akia, aws, gh, npm},
	}, nil
}
