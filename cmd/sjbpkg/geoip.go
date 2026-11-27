package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/stevejboyle/sjb-os/internal/geoip"
)

// geoipConvert downloads the newest DB-IP country database (or reads one
// given with -in) and writes it in the appliance's format to -o, for the
// copy that ships in the OVA and in bundles.
func geoipConvert(args []string) error {
	fs := flag.NewFlagSet("geoip-convert", flag.ExitOnError)
	in := fs.String("in", "", "a DB-IP country CSV (.csv.gz) instead of downloading")
	month := fs.String("month", "", "YYYY-MM of -in (default: this month)")
	out := fs.String("o", "", "output directory")
	fs.Parse(args)
	if *out == "" {
		return fmt.Errorf("usage: geoip-convert [-in FILE -month YYYY-MM] -o DIR")
	}
	now := time.Now()
	var db *geoip.DB
	if *in != "" {
		data, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		if db, err = geoip.Parse(bytes.NewReader(data), true); err != nil {
			return err
		}
		m := *month
		if m == "" {
			m = now.UTC().Format("2006-01")
		}
		db.SetMeta(m, "shipped", now)
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		var err error
		if db, err = geoip.Fetch(ctx, &http.Client{Timeout: 3 * time.Minute}, now, ""); err != nil {
			return err
		}
		db.SetMeta(db.Meta().Month, "shipped", now)
	}
	if err := db.Save(*out); err != nil {
		return err
	}
	m := db.Meta()
	fmt.Printf("country database %s: %d IPv4 rows, %d countries, sha256 %s\n", m.Month, m.Rows, m.Countries, m.SHA256)
	return nil
}
