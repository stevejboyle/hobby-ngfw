package appid

import (
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func src(now int64) Source {
	return Source{StatsFile: "testdata/stats.json", Now: func() time.Time { return time.Unix(now, 0) }}
}

func TestSeen(t *testing.T) {
	st := src(1794590565).Seen(true)
	if !st.Running || st.ActiveFlows != 3 || len(st.Apps) != 3 || st.Apps[0].Name != "YouTube" || st.Apps[0].Bytes != 3850 || st.Note != "" {
		t.Fatalf("status: %+v", st)
	}
	if st := src(1794590565 + 120).Seen(true); st.Running || !strings.Contains(st.Note, "stopped updating") {
		t.Fatalf("stale stats: %+v", st)
	}
	if st := src(0).Seen(false); !strings.Contains(st.Note, "App Identification is off") {
		t.Fatalf("off: %+v", st)
	}
	missing := Source{StatsFile: filepath.Join(t.TempDir(), "none.json")}
	if st := missing.Seen(true); st.Running || len(st.Apps) != 0 || !strings.Contains(st.Note, "isn't running yet") {
		t.Fatalf("missing: %+v", st)
	}
}

// The catalog is the one the build generated from nDPI.
func TestCatalog(t *testing.T) {
	all, err := src(0).Catalog("")
	if err != nil || len(all) < 400 {
		t.Fatalf("%d apps, %v", len(all), err)
	}
	yt, _ := src(0).Catalog("youtube")
	if len(yt) == 0 || yt[0].Name != "YouTube" || yt[0].Category != "Media" {
		t.Fatalf("youtube: %+v", yt)
	}
	media, _ := src(0).Catalog("media")
	if len(media) < 5 {
		t.Fatalf("category search: %d", len(media))
	}
}

func TestLookup(t *testing.T) {
	yt, ok := Lookup("YOUTUBE")
	if !ok || yt.Name != "YouTube" || yt.ID != 124 {
		t.Fatalf("lookup: %+v %v", yt, ok)
	}
	if _, ok := Lookup("no-such-app"); ok {
		t.Fatal("found a made-up app")
	}
	n := Names()
	if n[0] != Unknown || len(n) < 400 {
		t.Fatalf("names: %d, first %q", len(n), n[0])
	}
}

func TestCategories(t *testing.T) {
	cats := Categories()
	if len(cats) < 30 {
		t.Fatalf("%d categories", len(cats))
	}
	var media *Category
	for i := range cats {
		if cats[i].Name == "Media" {
			media = &cats[i]
		}
	}
	if media == nil || media.Ref != "category:media" || media.Apps < 5 {
		t.Fatalf("media: %+v", media)
	}
	apps, ok := CategoryApps("Category:MEDIA")
	if !ok || len(apps) != media.Apps {
		t.Fatalf("category apps: %d %v", len(apps), ok)
	}
	found := false
	for _, a := range apps {
		found = found || a.Name == "YouTube"
	}
	if !found {
		t.Fatal("YouTube not in category:media")
	}
	for _, bad := range []string{"category:", "category:nope", "media", "youtube"} {
		if _, ok := CategoryApps(bad); ok {
			t.Errorf("%q taken as a category", bad)
		}
	}
}

// The first lookups may come from several requests at once.
func TestCatalogConcurrent(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				Categories()
			case 1:
				Lookup("youtube")
			default:
				Names()
			}
		}(i)
	}
	wg.Wait()
}
