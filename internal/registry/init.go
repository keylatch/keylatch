package registry

import (
	"context"
	"path/filepath"

	"github.com/keylatch/keylatch/internal/llmcontext"
	"github.com/keylatch/keylatch/internal/paths"
	providers "github.com/keylatch/keylatch/templates/providers"
)

// InitFromConfig builds a CompositeLoader from:
//   - embedded Core-v1 templates (from templates/providers/core/*.yaml)
//   - user's local template directory (~/.keylatch/templates/providers/)
//   - community template directory (~/.keylatch/templates/community/) with sig requirement
//
// It registers all loaded templates with the global registry.
// The first slug encountered wins on collision (embed > local > community).
func InitFromConfig(ctx context.Context, env llmcontext.Lookup) error {
	embed := &EmbedLoader{FS: providers.EmbeddedFS, Tier: TierCore}

	localDir := filepath.Join(paths.ConfigDir(env), "templates", "providers")
	local := &FSLoader{Dir: localDir, Tier: TierLocal}

	community := &FSLoader{
		Dir:        filepath.Join(paths.ConfigDir(env), "templates", "community"),
		Tier:       TierCommunity,
		RequireSig: true,
	}

	composite := &CompositeLoader{Loaders: []Loader{embed, local, community}}
	templates, err := composite.LoadAll(ctx)
	if err != nil {
		return err
	}

	// Reset the catalog before registering so that repeated calls (e.g. from
	// `registry reload`) pick up changes rather than being silently idempotent.
	Reset()

	for _, lt := range templates {
		if regErr := Register(lt.Template); regErr != nil {
			return regErr
		}
	}
	return nil
}
