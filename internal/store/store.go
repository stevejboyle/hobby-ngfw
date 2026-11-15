// Package store keeps the candidate config and numbered committed revisions
// on disk:
//
//	<dir>/candidate.yaml
//	<dir>/revisions/000001.yaml   config as committed
//	<dir>/revisions/000001.json   metadata (time, author, message)
//	<dir>/running                 number of the running revision
//
// Writes go through a temp file and rename, so a crash never leaves a
// half-written file.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Revision describes one commit.
type Revision struct {
	N       int       `json:"n"`
	Time    time.Time `json:"time"`
	Author  string    `json:"author"`
	Message string    `json:"message"`
}

// Store is a directory of config revisions.
type Store struct {
	dir string
	// Fail, when set, is called before each write with its kind ("revision",
	// "running", "candidate", "pending") and fails the write when it returns
	// an error. For failure-injection tests.
	Fail func(op string) error
}

func (s *Store) fail(op string) error {
	if s.Fail == nil {
		return nil
	}
	return s.Fail(op)
}

// Open creates the directory layout if needed.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "revisions"), 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(parts ...string) string {
	return filepath.Join(append([]string{s.dir}, parts...)...)
}

// Candidate returns the candidate config. With no candidate saved, it is the
// running config (or empty when nothing has been committed).
func (s *Store) Candidate() ([]byte, error) {
	b, err := os.ReadFile(s.path("candidate.yaml"))
	if errors.Is(err, os.ErrNotExist) {
		_, run, err := s.Running()
		return run, err
	}
	return b, err
}

// SetCandidate replaces the candidate config.
func (s *Store) SetCandidate(data []byte) error {
	if err := s.fail("candidate"); err != nil {
		return err
	}
	return writeAtomic(s.path("candidate.yaml"), data)
}

// Running returns the running revision number and its config; 0 and nil
// when nothing has been committed.
func (s *Store) Running() (int, []byte, error) {
	b, err := os.ReadFile(s.path("running"))
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, nil, fmt.Errorf("corrupt running pointer: %w", err)
	}
	if n == 0 {
		return 0, nil, nil
	}
	data, err := s.Get(n)
	return n, data, err
}

// SetRunning points "running" at revision n (0 = nothing running).
func (s *Store) SetRunning(n int) error {
	if err := s.fail("running"); err != nil {
		return err
	}
	return writeAtomic(s.path("running"), []byte(strconv.Itoa(n)+"\n"))
}

// Get returns the config of revision n.
func (s *Store) Get(n int) ([]byte, error) {
	b, err := os.ReadFile(s.path("revisions", fmt.Sprintf("%06d.yaml", n)))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no revision %d", n)
	}
	return b, err
}

// Save writes data as the next revision and makes it running. The
// candidate becomes identical to running.
func (s *Store) Save(data []byte, author, message string, now time.Time) (Revision, error) {
	r, err := s.SaveRevision(data, author, message, now)
	if err != nil {
		return Revision{}, err
	}
	if err := s.SetRunning(r.N); err != nil {
		s.DeleteRevision(r.N)
		return Revision{}, err
	}
	return r, s.SetCandidate(data)
}

// SaveRevision writes data as the next revision without making it running.
// The metadata file goes last: List shows a revision only once both exist.
func (s *Store) SaveRevision(data []byte, author, message string, now time.Time) (Revision, error) {
	if err := s.fail("revision"); err != nil {
		return Revision{}, err
	}
	revs, err := s.List()
	if err != nil {
		return Revision{}, err
	}
	r := Revision{N: 1, Time: now.UTC(), Author: author, Message: message}
	if len(revs) > 0 {
		r.N = revs[len(revs)-1].N + 1
	}
	meta, _ := json.MarshalIndent(r, "", "  ")
	if err := writeAtomic(s.path("revisions", fmt.Sprintf("%06d.yaml", r.N)), data); err != nil {
		return Revision{}, err
	}
	if err := writeAtomic(s.path("revisions", fmt.Sprintf("%06d.json", r.N)), meta); err != nil {
		os.Remove(s.path("revisions", fmt.Sprintf("%06d.yaml", r.N)))
		return Revision{}, err
	}
	return r, nil
}

// DeleteRevision removes revision n: a commit that saved it and then
// failed. Best effort; the metadata goes first so List never shows half of one.
func (s *Store) DeleteRevision(n int) {
	os.Remove(s.path("revisions", fmt.Sprintf("%06d.json", n)))
	os.Remove(s.path("revisions", fmt.Sprintf("%06d.yaml", n)))
}

// List returns all revisions, oldest first.
func (s *Store) List() ([]Revision, error) {
	files, err := filepath.Glob(s.path("revisions", "*.json"))
	if err != nil {
		return nil, err
	}
	var revs []Revision
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var r Revision
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		revs = append(revs, r)
	}
	sort.Slice(revs, func(i, j int) bool { return revs[i].N < revs[j].N })
	return revs, nil
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Pending is a commit waiting for confirmation, kept on disk so the
// auto-rollback survives a restart of ngfwd (upgrade, reboot, crash).
type Pending struct {
	Revision int       `json:"revision"` // the unconfirmed revision
	Previous int       `json:"previous"` // what to restore (0 = no config)
	Deadline time.Time `json:"deadline"`
}

// SavePending records the pending confirmation.
func (s *Store) SavePending(p Pending) error {
	if err := s.fail("pending"); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path("pending.json"), append(b, '\n'))
}

// LoadPending returns the recorded pending confirmation, or nil.
func (s *Store) LoadPending() (*Pending, error) {
	b, err := os.ReadFile(s.path("pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("pending.json: %w", err)
	}
	return &p, nil
}

// ClearPending forgets the pending confirmation.
func (s *Store) ClearPending() error {
	if err := s.fail("pending"); err != nil {
		return err
	}
	err := os.Remove(s.path("pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
