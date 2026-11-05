package brokerd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/keylatch/keylatch/internal/backend"
	"github.com/keylatch/keylatch/internal/backend/brokerstore"
)

const retirementPrefix = ".sync/retirements/"

// retirementJob retains authorization and version identities, never source values.
type retirementJob struct {
	Version    int                    `json:"version"`
	Source     brokerstore.Retirement `json:"source"`
	Connection string                 `json:"connection"`
	Field      string                 `json:"field"`
	Name       string                 `json:"name"`
	Targets    []string               `json:"targets"`
	Presence   string                 `json:"presence"`
	VerifiedAt time.Time              `json:"verified_at"`
	NotBefore  time.Time              `json:"not_before"`
}

// retirementQueue uses the partition store so jobs share its encryption and rewrap.
type retirementQueue struct {
	mu    sync.Mutex
	store *brokerstore.Store
}

func (j retirementJob) validate() error {
	if j.Version != 1 {
		return errors.New("sync retirement: unsupported job version")
	}
	r := j.Source
	if r.Path == "" || len(r.Path) > 512 || path.Clean(r.Path) != r.Path || strings.HasPrefix(r.Path, "/") || r.Path == ".." || strings.HasPrefix(r.Path, "../") || strings.ContainsRune(r.Path, 0) || strings.HasPrefix(r.Path, ".sync/") {
		return errors.New("sync retirement: invalid source path")
	}
	if r.CurrentVersion < 2 || !retirementHex(r.CurrentID, 32) || !retirementHex(r.PreviousID, 32) || !retirementHex(j.Presence, 8) {
		return errors.New("sync retirement: invalid source identity or presence reference")
	}
	if j.Connection == "" || j.Name == "" || len(j.Connection) > 512 || len(j.Field) > 512 || len(j.Name) > 512 || len(j.Targets) == 0 || len(j.Targets) > 100 {
		return errors.New("sync retirement: invalid connection or targets")
	}
	seen := map[string]bool{}
	for _, target := range j.Targets {
		if target == "" || len(target) > 512 || seen[target] {
			return errors.New("sync retirement: invalid or duplicate target")
		}
		seen[target] = true
	}
	if j.VerifiedAt.IsZero() || j.NotBefore.Before(j.VerifiedAt) || j.NotBefore.Sub(j.VerifiedAt) > 24*time.Hour {
		return errors.New("sync retirement: invalid retention deadline")
	}
	return nil
}

func retirementHex(value string, size int) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == size && value == strings.ToLower(value)
}

func (j retirementJob) id() string {
	// A retried enqueue preserves the original verified time and retention deadline.
	j.VerifiedAt, j.NotBefore = time.Time{}, time.Time{}
	j.Targets = slices.Clone(j.Targets)
	slices.Sort(j.Targets)
	b, _ := json.Marshal(j)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (q *retirementQueue) enqueue(ctx context.Context, job retirementJob) (string, error) {
	if err := job.validate(); err != nil {
		return "", err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	id := job.id()
	if _, err := q.read(ctx, id); err == nil {
		return id, nil
	} else if !errors.Is(err, backend.ErrNotFound) {
		return "", err
	}
	job.Targets = slices.Clone(job.Targets)
	slices.Sort(job.Targets)
	b, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	defer clear(b)
	_, err = q.store.Put(ctx, retirementPrefix+id, b)
	return id, err
}

func (q *retirementQueue) read(ctx context.Context, id string) (retirementJob, error) {
	var job retirementJob
	if !retirementHex(id, 32) {
		return job, errors.New("sync retirement: invalid job identity")
	}
	b, _, err := q.store.Get(ctx, retirementPrefix+id)
	if err != nil {
		return job, err
	}
	defer clear(b)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		return retirementJob{}, errors.New("sync retirement: invalid job")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return retirementJob{}, errors.New("sync retirement: trailing job data")
	}
	if err := job.validate(); err != nil {
		return retirementJob{}, err
	}
	if job.id() != id {
		return retirementJob{}, errors.New("sync retirement: job identity mismatch")
	}
	return job, nil
}

func (q *retirementQueue) due(ctx context.Context, now time.Time) ([]retirementJob, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := q.store.List(ctx, retirementPrefix)
	if err != nil {
		return nil, err
	}
	var jobs []retirementJob
	for _, entry := range entries {
		id := strings.TrimPrefix(entry.Path, retirementPrefix)
		job, err := q.read(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("sync retirement: read pending job: %w", err)
		}
		if !now.Before(job.NotBefore) {
			jobs = append(jobs, job)
		}
	}
	slices.SortFunc(jobs, func(a, b retirementJob) int {
		if cmp := a.NotBefore.Compare(b.NotBefore); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.id(), b.id())
	})
	return jobs, nil
}

func (q *retirementQueue) complete(ctx context.Context, job retirementJob) error {
	if err := job.validate(); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	id := job.id()
	if _, err := q.read(ctx, id); errors.Is(err, backend.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	return q.store.Delete(ctx, retirementPrefix+id)
}
