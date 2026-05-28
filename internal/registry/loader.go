package registry

import (
	"context"
	"io/fs"
)

// Source identifies where a provider template was loaded from.
type Source string

const (
	SourceEmbed     Source = "embed"
	SourceLocal     Source = "local"
	SourceCommunity Source = "community"
)

// Tier classifies template stability.
type Tier string

const (
	TierCore         Tier = "core"
	TierSaaS         Tier = "saas"
	TierExperimental Tier = "experimental"
	TierLocal        Tier = "local"
	TierCommunity    Tier = "community"
)

// LoadedTemplate wraps a ConnectionTemplate with provenance metadata.
type LoadedTemplate struct {
	Template ConnectionTemplate
	Source   Source
	Tier     Tier
	Path     string // original file path or embedded name
	Signed   bool   // true if cosign signature verified
}

// Loader loads provider templates from some source.
type Loader interface {
	LoadAll(ctx context.Context) ([]LoadedTemplate, error)
}

// EmbedLoader loads templates from an embedded fs.FS.
type EmbedLoader struct {
	FS   fs.FS
	Tier Tier
}

// FSLoader loads templates from a filesystem directory.
type FSLoader struct {
	Dir        string
	Tier       Tier
	RequireSig bool
}

// CompositeLoader chains multiple loaders; first slug wins on collision.
type CompositeLoader struct {
	Loaders []Loader
}

// LoadAll implements Loader. Results from earlier loaders take precedence on
// slug collision.
func (c *CompositeLoader) LoadAll(ctx context.Context) ([]LoadedTemplate, error) {
	seen := make(map[string]bool)
	var result []LoadedTemplate
	for _, l := range c.Loaders {
		templates, err := l.LoadAll(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range templates {
			if !seen[t.Template.Provider] {
				seen[t.Template.Provider] = true
				result = append(result, t)
			}
		}
	}
	return result, nil
}
