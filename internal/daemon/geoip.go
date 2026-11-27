package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/geoip"
)

// geoState is the country and AS databases in use. Its fields are guarded
// by d.mu; d.geoLookup mirrors db and asn for lock-free lookups.
type geoState struct {
	store  *geoip.Store
	db     *geoip.DB
	asn    *geoip.ASNDB
	client *http.Client
	check  GeoIPCheck // the last update check (both databases)
}

// geoDBs is what GeoOf reads.
type geoDBs struct {
	db  *geoip.DB
	asn *geoip.ASNDB
}

// publishGeoLocked makes the databases in use visible to GeoOf.
func (d *Daemon) publishGeoLocked() {
	d.geoLookup.Store(&geoDBs{db: d.geo.db, asn: d.geo.asn})
}

// GeoOf returns the country and AS of an address for the logs: "" and 0
// for private and reserved ranges (DB-IP's ZZ), IPv6, bad input and
// missing data. It never takes d.mu, so reading logs never waits on a
// commit.
func (d *Daemon) GeoOf(addr string) (country string, asn uint32, org string) {
	g := d.geoLookup.Load()
	if g == nil {
		return "", 0, ""
	}
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return "", 0, ""
	}
	if cc := g.db.Lookup(a); cc != "ZZ" {
		country = cc
	}
	asn, org = g.asn.Lookup(a)
	return country, asn, org
}

// GeoIPCheck is the outcome of the last update check.
type GeoIPCheck struct {
	Time   time.Time `json:"time,omitempty"`
	OK     bool      `json:"ok"`
	Result string    `json:"result,omitempty"` // "up to date", "updated to 2026-11", or the error
}

const geoCheckFile = "check.json"

// SetGeoIP sets where the country and AS databases live and loads the ones
// in use. client (nil: a default) downloads new months.
func (d *Daemon) SetGeoIP(store geoip.Store, client *http.Client) {
	db, err := store.Current()
	if err != nil {
		d.log.Warn("country database unreadable; country rules match no address until it is replaced", "err", err)
		db = nil
	}
	asn, err := store.CurrentASN()
	if err != nil {
		d.log.Warn("AS database unreadable; logs show no AS until it is replaced", "err", err)
		asn = nil
	}
	var check GeoIPCheck
	if data, err := os.ReadFile(filepath.Join(store.Local, geoCheckFile)); err == nil {
		json.Unmarshal(data, &check)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.geo = &geoState{store: &store, db: db, asn: asn, client: client, check: check}
	d.publishGeoLocked()
}

// geoSource is the database for a compile (nil, not a nil pointer, when
// there is none). Callers hold d.mu.
func (d *Daemon) geoSource() compiler.GeoSource {
	if d.geo == nil || d.geo.db == nil {
		return nil
	}
	return d.geo.db
}

// GeoIPStatus is what `show geoip` and the web UI show.
type GeoIPStatus struct {
	Available   bool         `json:"available"` // a database is loaded
	Meta        geoip.Meta   `json:"meta"`
	AgeDays     int          `json:"age_days"` // since the database was installed
	AutoUpdate  bool         `json:"auto_update"`
	LastCheck   GeoIPCheck   `json:"last_check"`
	InUse       []GeoCountry `json:"in_use"` // countries the running rules use
	ASN         ASNStatus    `json:"asn"`    // the AS database (logs)
	Attribution string       `json:"attribution"`
}

// ASNStatus describes the AS database.
type ASNStatus struct {
	Available bool       `json:"available"`
	Meta      geoip.Meta `json:"meta"`
	AgeDays   int        `json:"age_days"`
}

// GeoCountry is a country the rules use.
type GeoCountry struct {
	Code   string `json:"code"`
	Name   string `json:"name"`
	Ranges int    `json:"ranges"`
}

// GeoIP reports the country database and the countries in use.
func (d *Daemon) GeoIP() GeoIPStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := GeoIPStatus{Attribution: geoip.Attribution, AutoUpdate: true, InUse: []GeoCountry{}}
	if d.running != nil {
		st.AutoUpdate = d.running.System.GeoIPAutoUpdateOn()
	}
	if d.geo == nil {
		return st
	}
	st.LastCheck = d.geo.check
	var counts map[string]int
	if db := d.geo.db; db != nil {
		st.Available, st.Meta = true, db.Meta()
		if !st.Meta.Installed.IsZero() {
			st.AgeDays = int(d.Now().Sub(st.Meta.Installed).Hours() / 24)
		}
		counts = db.Countries()
	}
	if a := d.geo.asn; a != nil {
		st.ASN = ASNStatus{Available: true, Meta: a.Meta()}
		if !st.ASN.Meta.Installed.IsZero() {
			st.ASN.AgeDays = int(d.Now().Sub(st.ASN.Meta.Installed).Hours() / 24)
		}
	}
	if d.running != nil {
		for _, cc := range compiler.UsedCountries(d.running) {
			st.InUse = append(st.InUse, GeoCountry{Code: cc, Name: geoip.Names[cc], Ranges: counts[cc]})
		}
	}
	return st
}

// GeoIPLookup returns the country and AS of an IPv4 address.
func (d *Daemon) GeoIPLookup(ip string) (map[string]string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("%w: %q is not an IPv4 address", ErrInvalid, ip)
	}
	g := d.geoLookup.Load()
	if g == nil || (g.db == nil && g.asn == nil) {
		return nil, fmt.Errorf("%w: there is no country or AS database yet", ErrInvalid)
	}
	cc := g.db.Lookup(a)
	if cc == "ZZ" { // DB-IP's private and reserved ranges
		cc = ""
	}
	out := map[string]string{"ip": ip, "country": cc, "name": geoip.Names[cc]}
	if n, org := g.asn.Lookup(a); n != 0 {
		out["asn"], out["as_org"] = fmt.Sprint(n), org
	}
	return out, nil
}

// installGeoLocked makes db the database in use and re-applies the running
// ruleset with its ranges (one atomic transaction; no new revision).
func (d *Daemon) installGeoLocked(db *geoip.DB) error {
	if err := d.geo.store.Install(db); err != nil {
		return fmt.Errorf("saving the country database: %w", err)
	}
	loaded, err := d.geo.store.Current()
	if err != nil {
		return err
	}
	d.geo.db = loaded
	d.publishGeoLocked()
	if d.running != nil && len(compiler.UsedCountries(d.running)) > 0 {
		if err := d.reapplyRunningLocked(); err != nil {
			return fmt.Errorf("applying the new country ranges: %w", err)
		}
	}
	return nil
}

// installASNLocked makes db the AS database in use (logs only: nothing to
// re-apply).
func (d *Daemon) installASNLocked(db *geoip.ASNDB) error {
	if err := d.geo.store.InstallASN(db); err != nil {
		return fmt.Errorf("saving the AS database: %w", err)
	}
	loaded, err := d.geo.store.CurrentASN()
	if err != nil {
		return err
	}
	d.geo.asn = loaded
	d.publishGeoLocked()
	return nil
}

func (d *Daemon) recordGeoCheckLocked(ok bool, result string) {
	d.geo.check = GeoIPCheck{Time: d.Now().UTC(), OK: ok, Result: result}
	if b, err := json.Marshal(d.geo.check); err == nil {
		os.MkdirAll(d.geo.store.Local, 0o755)
		os.WriteFile(filepath.Join(d.geo.store.Local, geoCheckFile), b, 0o644)
	}
}

// UpdateGeoIP downloads newer months of the country and AS databases, if
// there are any, and applies them. Each is checked on its own; the check's
// result says how each went.
func (d *Daemon) UpdateGeoIP(ctx context.Context) (GeoIPStatus, error) {
	d.mu.Lock()
	if d.geo == nil {
		d.mu.Unlock()
		return GeoIPStatus{}, fmt.Errorf("%w: geo-blocking isn't available here", ErrInvalid)
	}
	have, haveASN := "", ""
	if d.geo.db != nil {
		have = d.geo.db.Meta().Month
	}
	if d.geo.asn != nil {
		haveASN = d.geo.asn.Meta().Month
	}
	client := d.geo.client
	d.mu.Unlock()
	// The downloads run without the lock: commits go on meanwhile.
	db, err := geoip.Fetch(ctx, client, d.Now(), have)
	adb, aerr := geoip.FetchASN(ctx, client, d.Now(), haveASN)
	d.mu.Lock()
	var results []string
	var errs []error
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("country: %w", err))
		results = append(results, "country: "+err.Error())
	case db == nil:
		results = append(results, "country up to date ("+have+")")
	default:
		if err := d.installGeoLocked(db); err != nil {
			errs = append(errs, err)
			results = append(results, "country: "+err.Error())
		} else {
			results = append(results, "country updated to "+db.Meta().Month)
			d.log.Info("country database updated", "month", db.Meta().Month, "countries", db.Meta().Countries)
		}
	}
	switch {
	case aerr != nil:
		errs = append(errs, fmt.Errorf("AS: %w", aerr))
		results = append(results, "AS: "+aerr.Error())
	case adb == nil:
		results = append(results, "AS up to date ("+haveASN+")")
	default:
		if err := d.installASNLocked(adb); err != nil {
			errs = append(errs, err)
			results = append(results, "AS: "+err.Error())
		} else {
			results = append(results, "AS updated to "+adb.Meta().Month)
			d.log.Info("AS database updated", "month", adb.Meta().Month, "asns", adb.Meta().ASNs)
		}
	}
	d.recordGeoCheckLocked(len(errs) == 0, strings.Join(results, "; "))
	d.mu.Unlock()
	return d.GeoIP(), errors.Join(errs...)
}

// ImportGeoIP installs a DB-IP country or ASN CSV (gzipped or not; told
// apart by their columns) supplied by the operator, for appliances without
// internet access. It may be partial.
func (d *Daemon) ImportGeoIP(c accounts.Caller, data []byte) (GeoIPStatus, error) {
	if geoip.IsASNCSV(data) {
		return d.importASN(c, data)
	}
	db, err := geoip.Parse(bytes.NewReader(data), false)
	if err != nil {
		return GeoIPStatus{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	// It counts as this month's, so it stays in use until a newer month.
	db.SetMeta(d.Now().UTC().Format("2006-01"), "imported", d.Now())
	d.mu.Lock()
	if d.geo == nil {
		d.mu.Unlock()
		return GeoIPStatus{}, fmt.Errorf("%w: geo-blocking isn't available here", ErrInvalid)
	}
	err = d.installGeoLocked(db)
	if err == nil {
		d.recordGeoCheckLocked(true, "imported by "+c.Author())
	}
	d.mu.Unlock()
	if err != nil {
		return GeoIPStatus{}, err
	}
	d.log.Info("country database imported", "by", c.Author(), "rows", db.Meta().Rows, "countries", db.Meta().Countries)
	return d.GeoIP(), nil
}

func (d *Daemon) importASN(c accounts.Caller, data []byte) (GeoIPStatus, error) {
	db, err := geoip.ParseASN(bytes.NewReader(data), false)
	if err != nil {
		return GeoIPStatus{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	db.SetMeta(d.Now().UTC().Format("2006-01"), "imported", d.Now())
	d.mu.Lock()
	if d.geo == nil {
		d.mu.Unlock()
		return GeoIPStatus{}, fmt.Errorf("%w: geo-blocking isn't available here", ErrInvalid)
	}
	err = d.installASNLocked(db)
	if err == nil {
		d.recordGeoCheckLocked(true, "AS database imported by "+c.Author())
	}
	d.mu.Unlock()
	if err != nil {
		return GeoIPStatus{}, err
	}
	d.log.Info("AS database imported", "by", c.Author(), "rows", db.Meta().Rows, "asns", db.Meta().ASNs)
	return d.GeoIP(), nil
}

// RunGeoIPUpdates checks daily for newer months while auto-update is on:
// the logs use both databases whether or not rules name countries.
func (d *Daemon) RunGeoIPUpdates(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.mu.Lock()
		due := d.geoUpdateDueLocked()
		d.mu.Unlock()
		if !due {
			continue
		}
		if _, err := d.UpdateGeoIP(ctx); err != nil {
			d.log.Warn("country or AS database update failed", "err", err)
		}
	}
}

// geoUpdateDueLocked: auto-update is on and the last check was 23 hours
// ago or more (whether or not rules name countries).
func (d *Daemon) geoUpdateDueLocked() bool {
	return d.geo != nil && d.running != nil && d.running.System.GeoIPAutoUpdateOn() &&
		d.Now().Sub(d.geo.check.Time) >= 23*time.Hour
}

// geoMetricsLocked is the databases' state for monitoring (have false
// without geo support; asnAge nil without an AS database).
func (d *Daemon) geoMetricsLocked() (age float64, ok bool, inUse int, asnAge *float64, have bool) {
	if d.geo == nil {
		return 0, false, 0, nil, false
	}
	if d.geo.asn != nil && !d.geo.asn.Meta().Installed.IsZero() {
		a := d.Now().Sub(d.geo.asn.Meta().Installed).Seconds()
		asnAge = &a
	}
	if d.geo.db != nil && !d.geo.db.Meta().Installed.IsZero() {
		age = d.Now().Sub(d.geo.db.Meta().Installed).Seconds()
	}
	ok = d.geo.check.Time.IsZero() || d.geo.check.OK
	if d.running != nil {
		inUse = len(compiler.UsedCountries(d.running))
	}
	return age, ok, inUse, asnAge, true
}
