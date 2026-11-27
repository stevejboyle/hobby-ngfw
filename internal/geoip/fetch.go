package geoip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BaseURL is where DB-IP publishes the monthly country database.
var BaseURL = "https://download.db-ip.com/free"

// maxDownload caps a download (the real file is about 5 MB).
var maxDownload int64 = 64 << 20

// URL is the country file of one month.
func URL(month string) string { return URLFor(Source, month) }

// URLFor is one month's file of a database (Source or ASNSource).
func URLFor(source, month string) string {
	return fmt.Sprintf("%s/%s-%s.csv.gz", BaseURL, source, month)
}

// Months to try at time now: this month, then the previous one (DB-IP
// publishes early in the month).
func Months(now time.Time) []string {
	now = now.UTC()
	first := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	return []string{first.Format("2006-01"), first.AddDate(0, -1, 0).Format("2006-01")}
}

// Fetch downloads and validates the newest country month available at
// time now that is newer than have ("" for none). It returns nil, nil when
// have is already the newest.
func Fetch(ctx context.Context, client *http.Client, now time.Time, have string) (*DB, error) {
	data, m, err := fetchNewest(ctx, client, Source, now, have)
	if data == nil || err != nil {
		return nil, err
	}
	db, err := Parse(bytes.NewReader(data), true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", URLFor(Source, m), err)
	}
	db.SetMeta(m, "downloaded", now)
	return db, nil
}

// FetchASN is Fetch for the AS database.
func FetchASN(ctx context.Context, client *http.Client, now time.Time, have string) (*ASNDB, error) {
	data, m, err := fetchNewest(ctx, client, ASNSource, now, have)
	if data == nil || err != nil {
		return nil, err
	}
	db, err := ParseASN(bytes.NewReader(data), true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", URLFor(ASNSource, m), err)
	}
	db.SetMeta(m, "downloaded", now)
	return db, nil
}

// fetchNewest downloads the newest month of a source newer than have (nil
// data when have is already the newest). Only a month DB-IP hasn't
// published (404) falls back to the previous one; any other failure is an
// error, so a passing network fault never installs (or ships) an older
// month than it should.
func fetchNewest(ctx context.Context, client *http.Client, source string, now time.Time, have string) ([]byte, string, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	var errs []error
	for _, m := range Months(now) {
		if have != "" && m <= have {
			return nil, "", nil
		}
		data, err := get(ctx, client, URLFor(source, m))
		if errors.Is(err, errNotPublished) {
			errs = append(errs, err)
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return data, m, nil
	}
	return nil, "", fmt.Errorf("no %s database downloaded: %v", source, errs)
}

var errNotPublished = errors.New("not published yet")

func get(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SJB-OS geoip")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s: %w", url, errNotPublished)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDownload+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxDownload {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, maxDownload)
	}
	return b, nil
}
