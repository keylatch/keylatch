package brokerd

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/keylatch/keylatch/internal/brokerapi"
)

// Source is an in-user install being moved into the broker.
type Source interface {
	// Secrets decrypts the store with the old key-encryption key.
	Secrets(ctx context.Context) ([]brokerapi.Item, error)
	// PolicyFiles returns the policy files by relative name, nil when there are none.
	PolicyFiles() (map[string][]byte, error)
	// AuditHead returns the hash of the in-user audit chain head.
	AuditHead() (string, error)
	// RevokeTokens revokes every in-user gateway token and reports how many.
	RevokeTokens(ctx context.Context) (int, error)
	// Shred overwrites and removes the in-user key material and reports what it removed.
	Shred() ([]string, error)
}

// Daemon is the broker as the adopting user sees it.
type Daemon interface {
	Call(req brokerapi.Request) (brokerapi.Response, error)
}

// AdoptResult reports what Adopt moved.
type AdoptResult struct {
	Secrets       int      `json:"secrets"`
	Verified      int      `json:"verified"`
	PolicyFiles   int      `json:"policy_files"`
	TokensRevoked int      `json:"tokens_revoked"`
	Shredded      []string `json:"shredded"`
	OldAuditHead  string   `json:"old_audit_head,omitempty"`
	// RotateUpstream lists the upstream keys that sat in the user's account and
	// should be rotated.
	RotateUpstream []string `json:"rotate_upstream"`
}

// ErrVerify means a secret did not arrive intact.
var ErrVerify = errors.New("brokerd: a migrated secret failed its keyed-hash check")

// Prove asks the daemon for a presence proof covering req and returns req with
// the proof attached. The daemon shows the human a description it builds
// itself, so a modified client cannot misrepresent what is approved.
func Prove(d Daemon, req brokerapi.Request) (brokerapi.Request, error) {
	resp, err := d.Call(brokerapi.Request{Op: brokerapi.OpPresenceBegin, Target: &req})
	if err != nil {
		return req, err
	}
	if !resp.OK || resp.Proof == nil {
		return req, fmt.Errorf("presence: %s", resp.Error)
	}
	req.Proof = resp.Proof.ID
	return req, nil
}

// Adopt moves an in-user install into the daemon: the store, then the policy,
// then it revokes the in-user tokens and shreds the in-user key material. It
// shreds nothing unless every secret came back with a matching keyed hash.
func Adopt(ctx context.Context, src Source, d Daemon, rd io.Reader) (AdoptResult, error) {
	var res AdoptResult
	if rd == nil {
		rd = rand.Reader
	}
	items, err := src.Secrets(ctx)
	if err != nil {
		return res, fmt.Errorf("read the in-user store: %w", err)
	}
	head, err := src.AuditHead()
	if err != nil {
		return res, fmt.Errorf("read the in-user audit head: %w", err)
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rd, nonce); err != nil {
		return res, err
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Path < items[j].Path })
	req, err := Prove(d, brokerapi.Request{Op: brokerapi.OpMigrateImport, Items: items, Nonce: nonce, OldAuditHead: head})
	if err != nil {
		return res, err
	}
	resp, err := d.Call(req)
	if err != nil {
		return res, err
	}
	if !resp.OK {
		return res, fmt.Errorf("the broker refused the migration: %s", resp.Error)
	}
	res.Secrets, res.OldAuditHead = len(items), head
	if len(resp.MACs) != len(items) {
		return res, fmt.Errorf("%w: sent %d secrets, the broker confirmed %d", ErrVerify, len(items), len(resp.MACs))
	}
	for _, it := range items {
		if resp.MACs[it.Path] != KeyedHash(nonce, it.Path, it.Value) {
			return res, fmt.Errorf("%w: %s", ErrVerify, it.Path)
		}
		res.Verified++
		res.RotateUpstream = append(res.RotateUpstream, it.Path)
	}
	for _, it := range items {
		clear(it.Value)
	}

	files, err := src.PolicyFiles()
	if err != nil {
		return res, fmt.Errorf("read the in-user policy: %w", err)
	}
	if files != nil {
		pr, err := Prove(d, brokerapi.Request{Op: brokerapi.OpPolicyAccept, Files: files})
		if err != nil {
			return res, err
		}
		if resp, err := d.Call(pr); err != nil || !resp.OK {
			return res, fmt.Errorf("the broker refused the policy: %v %s", err, resp.Error)
		}
		res.PolicyFiles = len(files)
	}
	if res.TokensRevoked, err = src.RevokeTokens(ctx); err != nil {
		return res, fmt.Errorf("revoke the in-user gateway tokens: %w", err)
	}
	if res.Shredded, err = src.Shred(); err != nil {
		return res, fmt.Errorf("shred the in-user key material: %w", err)
	}
	return res, nil
}

// Sink receives secrets exported from the broker back into an in-user install.
type Sink interface {
	// Prepare makes the in-user install able to hold keys again.
	Prepare(ctx context.Context) error
	Put(ctx context.Context, path string, value []byte) error
}

// ExportToUser copies every secret back into an in-user install after a
// presence proof, for a downgrade. The broker keeps its copy.
func ExportToUser(ctx context.Context, d Daemon, sink Sink) (int, error) {
	req, err := Prove(d, brokerapi.Request{Op: brokerapi.OpMigrateExport})
	if err != nil {
		return 0, err
	}
	resp, err := d.Call(req)
	if err != nil {
		return 0, err
	}
	if !resp.OK {
		return 0, fmt.Errorf("the broker refused the export: %s", resp.Error)
	}
	if err := sink.Prepare(ctx); err != nil {
		return 0, fmt.Errorf("prepare the in-user install: %w", err)
	}
	for i, it := range resp.Items {
		if err := sink.Put(ctx, it.Path, it.Value); err != nil {
			return i, fmt.Errorf("restore %s: %w", it.Path, err)
		}
		clear(it.Value)
	}
	return len(resp.Items), nil
}
