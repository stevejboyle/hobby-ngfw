package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/stevejboyle/sjb-os/internal/accounts"
	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/geoip"
)

// geoState is the country database in use. Its fields are guarded by d.mu.
type geoState struct {
	store  *geoip.Store
	db     *geoip.DB
	client *http.Client
	check  GeoIPCheck // the last update check
}

// GeoIPCheck is the outcome of the last update check.
type GeoIPCheck struct {
	Time   time.Time `json:"time,omitempty"`
	OK     bool      `json:"ok"`
	Result string    `json:"result,omitempty"` // "up to date", "updated to 2026-11", or the error
}

const geoCheckFile = "check.json"

// SetGeoIP sets where country databases live and loads the one in use.
// client (nil: a default) downloads new months.
func (d *Daemon) SetGeoIP(store geoip.Store, client *http.Client) {
	db, err := store.Current()
	if err != nil {
		d.log.Warn("country database unreadable; country rules match no address until it is replaced", "err", err)
		db = nil
	}
	var check GeoIPCheck
	if data, err := os.ReadFile(filepath.Join(store.Local, geoCheckFile)); err == nil {
		json.Unmarshal(data, &check)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.geo = &geoState{store: &store, db: db, client: client, check: check}
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
	Attribution string       `json:"attribution"`
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
	if d.running != nil {
		for _, cc := range compiler.UsedCountries(d.running) {
			st.InUse = append(st.InUse, GeoCountry{Code: cc, Name: geoip.Names[cc], Ranges: counts[cc]})
		}
	}
	return st
}

// GeoIPLookup returns the country of an IPv4 address.
func (d *Daemon) GeoIPLookup(ip string) (map[string]string, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || !a.Is4() {
		return nil, fmt.Errorf("%w: %q is not an IPv4 address", ErrInvalid, ip)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.geo == nil || d.geo.db == nil {
		return nil, fmt.Errorf("%w: there is no country database yet", ErrInvalid)
	}
	cc := d.geo.db.Lookup(a)
	return map[string]string{"ip": ip, "country": cc, "name": geoip.Names[cc]}, nil
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
	if d.running != nil && len(compiler.UsedCountries(d.running)) > 0 {
		if err := d.reapplyRunningLocked(); err != nil {
			return fmt.Errorf("applying the new country ranges: %w", err)
		}
	}
	return nil
}

func (d *Daemon) recordGeoCheckLocked(ok bool, result string) {
	d.geo.check = GeoIPCheck{Time: d.Now().UTC(), OK: ok, Result: result}
	if b, err := json.Marshal(d.geo.check); err == nil {
		os.MkdirAll(d.geo.store.Local, 0o755)
		os.WriteFile(filepath.Join(d.geo.store.Local, geoCheckFile), b, 0o644)
	}
}

// UpdateGeoIP downloads a newer month of the country database, if there is
// one, and applies it.
func (d *Daemon) UpdateGeoIP(ctx context.Context) (GeoIPStatus, error) {
	d.mu.Lock()
	if d.geo == nil {
		d.mu.Unlock()
		return GeoIPStatus{}, fmt.Errorf("%w: geo-blocking isn't available here", ErrInvalid)
	}
	have := ""
	if d.geo.db != nil {
		have = d.geo.db.Meta().Month
	}
	client := d.geo.client
	d.mu.Unlock()
	// The download runs without the lock: commits go on meanwhile.
	db, err := geoip.Fetch(ctx, client, d.Now(), have)
	d.mu.Lock()
	switch {
	case err != nil:
		d.recordGeoCheckLocked(false, err.Error())
	case db == nil:
		d.recordGeoCheckLocked(true, "up to date ("+have+")")
	default:
		if err = d.installGeoLocked(db); err != nil {
			d.recordGeoCheckLocked(false, err.Error())
		} else {
			d.recordGeoCheckLocked(true, "updated to "+db.Meta().Month)
			d.log.Info("country database updated", "month", db.Meta().Month, "countries", db.Meta().Countries)
		}
	}
	d.mu.Unlock()
	return d.GeoIP(), err
}

// ImportGeoIP installs a DB-IP country CSV (gzipped or not) supplied by the
// operator, for appliances without internet access. It may be partial.
func (d *Daemon) ImportGeoIP(c accounts.Caller, data []byte) (GeoIPStatus, error) {
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

// RunGeoIPUpdates checks daily for a newer month while rules use countries
// and auto-update is on.
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
		due := d.geo != nil && d.running != nil && d.running.System.GeoIPAutoUpdateOn() &&
			len(compiler.UsedCountries(d.running)) > 0 && d.Now().Sub(d.geo.check.Time) >= 23*time.Hour
		d.mu.Unlock()
		if !due {
			continue
		}
		if _, err := d.UpdateGeoIP(ctx); err != nil {
			d.log.Warn("country database update failed", "err", err)
		}
	}
}

// geoMetricsLocked is the database's state for monitoring (nil without one).
func (d *Daemon) geoMetricsLocked() (age float64, ok bool, inUse int, have bool) {
	if d.geo == nil {
		return 0, false, 0, false
	}
	if d.geo.db != nil && !d.geo.db.Meta().Installed.IsZero() {
		age = d.Now().Sub(d.geo.db.Meta().Installed).Seconds()
	}
	ok = d.geo.check.Time.IsZero() || d.geo.check.OK
	if d.running != nil {
		inUse = len(compiler.UsedCountries(d.running))
	}
	return age, ok, inUse, true
}
