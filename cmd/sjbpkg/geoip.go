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

// geoipConvert downloads the newest DB-IP country and ASN databases (or
// reads ones given with -in and -asn-in) and writes them in the
// appliance's format to -o, for the copies that ship in the OVA and in
// bundles.
func geoipConvert(args []string) error {
	fs := flag.NewFlagSet("geoip-convert", flag.ExitOnError)
	in := fs.String("in", "", "a DB-IP country CSV (.csv.gz) instead of downloading")
	asnIn := fs.String("asn-in", "", "a DB-IP ASN CSV (.csv.gz) instead of downloading")
	month := fs.String("month", "", "YYYY-MM of -in and -asn-in (default: this month)")
	out := fs.String("o", "", "output directory")
	fs.Parse(args)
	if *out == "" || (*in == "") != (*asnIn == "") {
		return fmt.Errorf("usage: geoip-convert [-in FILE -asn-in FILE [-month YYYY-MM]] -o DIR")
	}
	now := time.Now()
	m := *month
	if m == "" {
		m = now.UTC().Format("2006-01")
	}
	var db *geoip.DB
	var adb *geoip.ASNDB
	if *in != "" {
		data, err := os.ReadFile(*in)
		if err != nil {
			return err
		}
		if db, err = geoip.Parse(bytes.NewReader(data), true); err != nil {
			return err
		}
		if data, err = os.ReadFile(*asnIn); err != nil {
			return err
		}
		if adb, err = geoip.ParseASN(bytes.NewReader(data), true); err != nil {
			return err
		}
		db.SetMeta(m, "shipped", now)
		adb.SetMeta(m, "shipped", now)
	} else {
		var err error
		if err = retry(func(ctx context.Context, c *http.Client) error {
			db, err = geoip.Fetch(ctx, c, now, "")
			return err
		}); err != nil {
			return err
		}
		if err = retry(func(ctx context.Context, c *http.Client) error {
			adb, err = geoip.FetchASN(ctx, c, now, "")
			return err
		}); err != nil {
			return err
		}
		db.SetMeta(db.Meta().Month, "shipped", now)
		adb.SetMeta(adb.Meta().Month, "shipped", now)
	}
	if err := db.Save(*out); err != nil {
		return err
	}
	if err := adb.Save(*out); err != nil {
		return err
	}
	dm, am := db.Meta(), adb.Meta()
	fmt.Printf("country database %s: %d IPv4 rows, %d countries, sha256 %s\n", dm.Month, dm.Rows, dm.Countries, dm.SHA256)
	fmt.Printf("AS database %s: %d IPv4 rows, %d ASes, sha256 %s\n", am.Month, am.Rows, am.ASNs, am.SHA256)
	return nil
}

// retry runs a download a few times: one network hiccup shouldn't fail a
// release build.
func retry(fetch func(context.Context, *http.Client) error) error {
	var err error
	for try := 1; try <= 3; try++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		err = fetch(ctx, &http.Client{Timeout: 3 * time.Minute})
		cancel()
		if err == nil {
			return nil
		}
		fmt.Fprintf(os.Stderr, "geoip-convert: try %d: %v\n", try, err)
		time.Sleep(time.Duration(try) * 10 * time.Second)
	}
	return err
}
