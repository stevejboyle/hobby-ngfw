package store

import (
	"testing"
	"time"
)

func TestLifecycle(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if n, data, err := s.Running(); n != 0 || data != nil || err != nil {
		t.Fatalf("fresh store: got %d %q %v", n, data, err)
	}
	if c, _ := s.Candidate(); c != nil {
		t.Fatalf("fresh candidate should be empty, got %q", c)
	}

	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	r1, err := s.Save([]byte("one"), "steve", "first", now)
	if err != nil || r1.N != 1 {
		t.Fatalf("save 1: %v %v", r1, err)
	}
	if err := s.SetCandidate([]byte("draft")); err != nil {
		t.Fatal(err)
	}
	if c, _ := s.Candidate(); string(c) != "draft" {
		t.Fatalf("candidate = %q", c)
	}
	r2, _ := s.Save([]byte("two"), "steve", "second", now.Add(time.Minute))
	if r2.N != 2 {
		t.Fatalf("want revision 2, got %d", r2.N)
	}
	if c, _ := s.Candidate(); string(c) != "two" {
		t.Fatalf("candidate after commit = %q, want running", c)
	}
	n, data, _ := s.Running()
	if n != 2 || string(data) != "two" {
		t.Fatalf("running = %d %q", n, data)
	}
	if err := s.SetRunning(1); err != nil {
		t.Fatal(err)
	}
	if n, data, _ := s.Running(); n != 1 || string(data) != "one" {
		t.Fatalf("running after SetRunning(1) = %d %q", n, data)
	}
	revs, _ := s.List()
	if len(revs) != 2 || revs[0].Message != "first" || revs[1].N != 2 {
		t.Fatalf("list = %+v", revs)
	}
	if _, err := s.Get(9); err == nil {
		t.Fatal("expected error for missing revision")
	}
}
