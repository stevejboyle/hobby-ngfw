package diff

import "testing"

func TestLines(t *testing.T) {
	if got := Lines("a\nb\n", "a\nb\n"); got != "" {
		t.Fatalf("equal inputs: %q", got)
	}
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n"
	b := "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\n11\n12\nthirteen\n"
	want := "  3\n  4\n- 5\n+ five\n  6\n  7\n...\n  11\n  12\n+ thirteen\n"
	if got := Lines(a, b); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if got := Lines("", "x\n"); got != "+ x\n" {
		t.Fatalf("from empty: %q", got)
	}
}
