package nfqueue

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nfnetlink_queue")
	os.WriteFile(p, []byte(
		"    0  12345     0 2 65531     0     0       10  1\n"+
			"    1  12346     0 2 65531     0     0       11  1\n"+
			"    2  22222     3 2 65531     7     1      500  1\n"), 0o644)
	if st := Read(p, 0, 1); !st.Bound || st.Dropped != 0 {
		t.Fatalf("queues 0-1: %+v", st)
	}
	// Queue 3 has no listener: not bound, whatever queue 2 does.
	if st := Read(p, 2, 3); st.Bound || st.Dropped != 8 {
		t.Fatalf("queues 2-3: %+v", st)
	}
	if st := Read(filepath.Join(t.TempDir(), "missing"), 2, 3); st.Bound {
		t.Fatal("no table: nothing is bound")
	}
}
