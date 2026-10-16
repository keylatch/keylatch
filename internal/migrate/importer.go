package migrate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// Import outcomes.
const (
	OutcomeWritten    = "written"
	OutcomeUnchanged  = "unchanged"
	OutcomeWouldWrite = "would-write"
	OutcomeFailed     = "failed"
)

// ItemResult is what happened to one item. It never holds a value.
type ItemResult struct {
	Path    string `json:"path"`
	Outcome string `json:"outcome"`
	Error   string `json:"error,omitempty"`
}

// ImportResult summarises an import.
type ImportResult struct {
	DryRun    bool         `json:"dry_run"`
	Written   int          `json:"written"`
	Unchanged int          `json:"unchanged"`
	Failed    int          `json:"failed"`
	Items     []ItemResult `json:"items"`
	// Manifest is set when the import was given a key.
	Manifest *Manifest `json:"-"`
}

// ImportOptions tunes Import.
type ImportOptions struct {
	DryRun bool
	// Key, with KDF, makes Import record a keyed hash of every item.
	Key []byte
	KDF KDF
}

// Import reads each planned value from its source and writes it to store. An
// item whose stored value already equals the source is left alone, so running
// it twice writes nothing the second time. A dry run reads and compares but
// writes nothing.
func Import(ctx context.Context, plan Plan, env Env, store Store, opt ImportOptions) ImportResult {
	res := ImportResult{DryRun: opt.DryRun, Items: []ItemResult{}}
	if opt.Key != nil {
		res.Manifest = &Manifest{Version: 1, KDF: opt.KDF, Items: []ManifestItem{}}
	}
	for _, it := range plan.Items {
		out := ItemResult{Path: it.Path}
		val, err := ReadValue(ctx, it, env)
		if err == nil {
			err = importOne(ctx, it, val, store, opt, &out)
			if err == nil && res.Manifest != nil {
				res.Manifest.Items = append(res.Manifest.Items, ManifestItem{Path: it.Path, MAC: MAC(opt.Key, val)})
			}
			clear(val)
		}
		if err != nil {
			out.Outcome, out.Error = OutcomeFailed, err.Error()
			res.Failed++
		}
		switch out.Outcome {
		case OutcomeWritten:
			res.Written++
		case OutcomeUnchanged:
			res.Unchanged++
		}
		res.Items = append(res.Items, out)
	}
	if f, ok := store.(Flusher); ok && !opt.DryRun && res.Written > 0 {
		if err := f.Flush(ctx); err != nil {
			for i := range res.Items {
				if res.Items[i].Outcome == OutcomeWritten {
					res.Items[i].Outcome, res.Items[i].Error = OutcomeFailed, err.Error()
				}
			}
			res.Failed += res.Written
			res.Written = 0
		}
	}
	return res
}

func importOne(ctx context.Context, it PlanItem, val []byte, store Store, opt ImportOptions, out *ItemResult) error {
	if len(val) == 0 {
		return errors.New("the source holds an empty value")
	}
	cur, err := store.Get(ctx, it.Path)
	switch {
	case err == nil:
		same := bytes.Equal(cur, val)
		clear(cur)
		if same {
			out.Outcome = OutcomeUnchanged
			return nil
		}
	case errors.Is(err, ErrUnreadable):
		out.Outcome = OutcomeUnchanged
		return nil
	case !errors.Is(err, ErrNotFound):
		return fmt.Errorf("read the target: %w", err)
	}
	if opt.DryRun {
		out.Outcome = OutcomeWouldWrite
		return nil
	}
	if err := store.Put(ctx, it.Path, val); err != nil {
		return fmt.Errorf("write the target: %w", err)
	}
	out.Outcome = OutcomeWritten
	return nil
}
