package daemon

import (
	"fmt"

	"github.com/stevejboyle/hobby-ngfw/internal/appid"
)

// SetAppID sets where App Identification's catalog and statistics are read. Call before
// serving.
func (d *Daemon) SetAppID(s appid.Source) { d.appid = s }

// Apps reports the applications App Identification has seen.
func (d *Daemon) Apps() appid.Status {
	d.mu.Lock()
	on := d.running == nil || d.running.System.AppIDOn()
	d.mu.Unlock()
	return d.appid.Seen(on)
}

// AppCatalog lists the applications App Identification can identify, filtered by q.
func (d *Daemon) AppCatalog(q string) ([]appid.App, error) {
	apps, err := d.appid.Catalog(q)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return apps, nil
}

// AppCategories lists App Identification's application categories.
func (d *Daemon) AppCategories() []appid.Category { return appid.Categories() }

// RuleName names the rule at position idx in the running config ("" if
// none), for App Identification's end-of-connection log entries.
func (d *Daemon) RuleName(idx int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.running == nil || idx < 0 || idx >= len(d.running.Rules) {
		return ""
	}
	return d.running.Rules[idx].Name
}
