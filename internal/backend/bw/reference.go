package bw

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/keylatch/keylatch/internal/backend"
	kexec "github.com/keylatch/keylatch/internal/exec"
	"github.com/keylatch/keylatch/internal/store"
)

func init() {
	store.RegisterSchemeResolver("bw", func(ctx context.Context, runner store.CommandRunner, bin, rest string) ([]byte, error) {
		ref, err := store.ParseBWRef(rest)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", store.ErrInvalidURI, err)
		}
		b, err := Open(Options{Bin: bin, Runner: runner})
		if err != nil {
			return nil, err
		}
		return b.ResolveRef(ctx, ref)
	})
}

// ResolveRef returns the plaintext value a bw:// reference points at, using
// the backend's BW_SESSION handling. The item is looked up on every call.
func (b *BitwardenBackend) ResolveRef(ctx context.Context, ref store.BWRef) ([]byte, error) {
	item, _, err := b.locateRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	defer zeroItem(&item)
	return refValue(item, ref)
}

// CanonicalizeRef resolves the scope and item of a reference to IDs, checks
// that the field exists and returns the ID-based reference to store. Names
// that match more than one item are rejected.
func CanonicalizeRef(ctx context.Context, runner kexec.CommandRunner, bin string, ref store.BWRef) (store.BWRef, error) {
	b, err := Open(Options{Bin: bin, Runner: runner})
	if err != nil {
		return store.BWRef{}, err
	}
	item, orgID, err := b.locateRef(ctx, ref)
	if err != nil {
		return store.BWRef{}, err
	}
	defer zeroItem(&item)
	v, err := refValue(item, ref)
	if err != nil {
		return store.BWRef{}, err
	}
	for i := range v {
		v[i] = 0
	}
	scope := store.BWPersonal
	if orgID != "" {
		scope = orgID
	}
	return store.BWRef{Scope: scope, Collection: store.BWAny, Item: item.ID, Field: ref.Field}, nil
}

func zeroItem(item *bwItem) {
	for i := range item.Fields {
		item.Fields[i].zero()
	}
	if item.Login != nil {
		item.Login.zero()
	}
	item.Notes = ""
}

func refValue(item bwItem, ref store.BWRef) ([]byte, error) {
	var val string
	switch name := ref.CustomFieldName(); {
	case name != "":
		found := -1
		for i, f := range item.Fields {
			if f.Name != name {
				continue
			}
			if found >= 0 {
				return nil, fmt.Errorf("bw: item %s has more than one custom field %q", item.ID, name)
			}
			found = i
		}
		if found < 0 {
			return nil, fmt.Errorf("%w: custom field %q not found in Bitwarden item %s", backend.ErrNotFound, name, item.ID)
		}
		val = string(item.Fields[found].Value)
	case strings.EqualFold(ref.Field, "notes"):
		val = item.Notes
	case item.Login == nil:
		return nil, fmt.Errorf("%w: Bitwarden item %s has no login", backend.ErrNotFound, item.ID)
	case strings.EqualFold(ref.Field, "username"):
		val = item.Login.Username
	default:
		val = item.Login.Password
	}
	if val == "" {
		return nil, fmt.Errorf("%w: field %q is empty or missing in Bitwarden item %s", backend.ErrNotFound, ref.Field, item.ID)
	}
	return []byte(val), nil
}

// locateRef finds the single item a reference names and returns it with the
// organization ID of its scope ("" for the personal vault).
func (b *BitwardenBackend) locateRef(ctx context.Context, ref store.BWRef) (bwItem, string, error) {
	orgID := ""
	if ref.Scope != store.BWPersonal {
		id, err := b.resolveOrg(ctx, ref.Scope)
		if err != nil {
			return bwItem{}, "", err
		}
		orgID = id
	}

	if ref.ItemIsID() {
		item, err := b.fetchItemDirect(ctx, ref.Item)
		if err != nil {
			return bwItem{}, "", err
		}
		if item.OrganizationID != orgID {
			return bwItem{}, "", fmt.Errorf("%w: item %s is not in scope %q", backend.ErrNotFound, ref.Item, ref.Scope)
		}
		if ref.Collection != store.BWAny {
			if err := b.checkPlacement(ctx, item, orgID, ref.Collection); err != nil {
				return bwItem{}, "", err
			}
		}
		return item, orgID, nil
	}

	args := []string{"list", "items", "--search=" + ref.Item}
	switch {
	case orgID != "":
		args = append(args, "--organizationid="+orgID)
		if ref.Collection != store.BWAny {
			cid, err := b.resolveCollection(ctx, orgID, ref.Collection)
			if err != nil {
				return bwItem{}, "", err
			}
			args = append(args, "--collectionid="+cid)
		}
	case ref.Collection != store.BWAny:
		fid, err := b.resolveFolderRef(ctx, ref.Collection)
		if err != nil {
			return bwItem{}, "", err
		}
		args = append(args, "--folderid="+fid)
	}
	var items []bwItem
	if err := b.runJSON(ctx, args, &items); err != nil {
		return bwItem{}, "", err
	}
	var match []bwItem
	for _, it := range items {
		if it.Name == ref.Item && it.OrganizationID == orgID {
			match = append(match, it)
		} else {
			zeroItem(&it)
		}
	}
	switch len(match) {
	case 0:
		return bwItem{}, "", fmt.Errorf("%w: no Bitwarden item named %q in scope %q", backend.ErrNotFound, ref.Item, ref.Scope)
	case 1:
		return match[0], orgID, nil
	}
	ids := make([]string, len(match))
	for i := range match {
		ids[i] = match[i].ID
		zeroItem(&match[i])
	}
	return bwItem{}, "", fmt.Errorf("bw: %d items are named %q in scope %q (ids: %s); use an item ID in the reference",
		len(ids), ref.Item, ref.Scope, strings.Join(ids, ", "))
}

func (b *BitwardenBackend) checkPlacement(ctx context.Context, item bwItem, orgID, name string) error {
	if orgID != "" {
		cid, err := b.resolveCollection(ctx, orgID, name)
		if err != nil {
			return err
		}
		for _, c := range item.CollectionIDs {
			if c == cid {
				return nil
			}
		}
	} else {
		fid, err := b.resolveFolderRef(ctx, name)
		if err != nil {
			return err
		}
		if item.FolderID != nil && *item.FolderID == fid {
			return nil
		}
	}
	return fmt.Errorf("%w: item %s is not in %q", backend.ErrNotFound, item.ID, name)
}

func (b *BitwardenBackend) resolveOrg(ctx context.Context, scope string) (string, error) {
	var orgs []bwNamed
	if err := b.runJSON(ctx, []string{"list", "organizations"}, &orgs); err != nil {
		return "", err
	}
	return pickNamed(orgs, scope, "organization")
}

func (b *BitwardenBackend) resolveCollection(ctx context.Context, orgID, name string) (string, error) {
	var cols []bwNamed
	if err := b.runJSON(ctx, []string{"list", "collections", "--organizationid=" + orgID}, &cols); err != nil {
		return "", err
	}
	return pickNamed(cols, name, "collection")
}

func (b *BitwardenBackend) resolveFolderRef(ctx context.Context, name string) (string, error) {
	var folders []bwNamed
	if err := b.runJSON(ctx, []string{"list", "folders"}, &folders); err != nil {
		return "", err
	}
	return pickNamed(folders, name, "folder")
}

// pickNamed matches by ID first, then by exact name; several name matches are
// ambiguous.
func pickNamed(list []bwNamed, key, kind string) (string, error) {
	for _, n := range list {
		if n.ID == key {
			return n.ID, nil
		}
	}
	var ids []string
	for _, n := range list {
		if n.Name == key {
			ids = append(ids, n.ID)
		}
	}
	switch len(ids) {
	case 0:
		return "", fmt.Errorf("%w: no Bitwarden %s %q", backend.ErrNotFound, kind, key)
	case 1:
		return ids[0], nil
	}
	return "", fmt.Errorf("bw: %d %ss are named %q (ids: %s); use the ID in the reference", len(ids), kind, key, strings.Join(ids, ", "))
}

// runJSON runs a bw command and decodes its JSON output into out. An empty
// success output means a locked or stale session.
func (b *BitwardenBackend) runJSON(ctx context.Context, args []string, out any) error {
	if err := b.checkServer(ctx); err != nil {
		return err
	}
	if b.opts.AutoSync {
		if err := b.sync(ctx); err != nil {
			return err
		}
	}
	return b.runJSONNoSync(ctx, args, out)
}

// runJSONNoSync is runJSON for callers that have already synced.
func (b *BitwardenBackend) runJSONNoSync(ctx context.Context, args []string, out any) error {
	stdout, stderr, exitCode, err := b.runWithSession(ctx, args, nil)
	if err != nil {
		return fmt.Errorf("bw %s: runner error: %w", args[0], err)
	}
	if exitCode != 0 {
		if isLocked(string(stderr)) {
			return b.lockedGuidance()
		}
		return fmt.Errorf("bw %s: bw exited %d", args[0], exitCode)
	}
	if len(stdout) == 0 {
		return b.lockedGuidance()
	}
	if err := json.Unmarshal(stdout, out); err != nil {
		return fmt.Errorf("bw %s: decode response: %w", args[0], err)
	}
	return nil
}
