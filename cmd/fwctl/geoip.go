package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

// geoipStatus mirrors daemon.GeoIPStatus.
type geoipStatus struct {
	Available bool `json:"available"`
	Meta      struct {
		Source    string    `json:"source"`
		Month     string    `json:"month"`
		Origin    string    `json:"origin"`
		Rows      int       `json:"rows"`
		Countries int       `json:"countries"`
		Installed time.Time `json:"installed"`
	} `json:"meta"`
	AgeDays    int  `json:"age_days"`
	AutoUpdate bool `json:"auto_update"`
	LastCheck  struct {
		Time   time.Time `json:"time"`
		OK     bool      `json:"ok"`
		Result string    `json:"result"`
	} `json:"last_check"`
	InUse []struct {
		Code   string `json:"code"`
		Name   string `json:"name"`
		Ranges int    `json:"ranges"`
	} `json:"in_use"`
	Attribution string `json:"attribution"`
}

func printGeoIP(out []byte) error {
	var st geoipStatus
	if err := json.Unmarshal(out, &st); err != nil {
		return err
	}
	if !st.Available {
		fmt.Println("country database: none yet (request geoip update, or fwctl geoip import FILE as root)")
	} else {
		m := st.Meta
		fmt.Printf("country database: DB-IP country lite %s (%s %s, %d days ago), %d IPv4 ranges in %d countries\n",
			m.Month, m.Origin, m.Installed.Local().Format("2006-01-02"), st.AgeDays, m.Rows, m.Countries)
	}
	auto := "on"
	if !st.AutoUpdate {
		auto = "off (set system geoip-auto-update on)"
	}
	fmt.Printf("auto-update:      %s; checked daily while rules use countries\n", auto)
	if !st.LastCheck.Time.IsZero() {
		res := st.LastCheck.Result
		if !st.LastCheck.OK {
			res = "FAILED: " + res
		}
		fmt.Printf("last check:       %s, %s\n", st.LastCheck.Time.Local().Format("2006-01-02 15:04"), res)
	}
	if len(st.InUse) == 0 {
		fmt.Println("countries in use: none (rules name countries as country:US)")
	} else {
		fmt.Println("countries in use:")
		for _, c := range st.InUse {
			note := ""
			if c.Ranges == 0 {
				note = "  NO ADDRESSES: rules naming it match nothing"
			}
			fmt.Printf("  %-3s %-32s %6d ranges%s\n", c.Code, c.Name, c.Ranges, note)
		}
	}
	fmt.Println(st.Attribution)
	return nil
}

func showGeoIP() error {
	out, err := call("GET", "/v1/geoip", nil)
	if err != nil {
		return err
	}
	return printGeoIP(out)
}

func showGeoIPLookup(ip string) error {
	out, err := call("GET", "/v1/geoip/lookup?ip="+url.QueryEscape(ip), nil)
	if err != nil {
		return err
	}
	var r map[string]string
	json.Unmarshal(out, &r)
	if r["country"] == "" {
		fmt.Printf("%s: no country (private, reserved or unlisted)\n", ip)
		return nil
	}
	fmt.Printf("%s: %s (%s), country:%s in rules\n", ip, r["country"], r["name"], r["country"])
	return nil
}

func requestGeoIPUpdate() error {
	fmt.Println("checking DB-IP for a newer country database...")
	out, err := call("POST", "/v1/geoip/update", nil)
	if err != nil {
		return err
	}
	return printGeoIP(out)
}

// geoipCmd: `fwctl geoip [status]`, `fwctl geoip import FILE` (a DB-IP
// country CSV, .csv or .csv.gz, for appliances without internet access).
func geoipCmd(args []string) error {
	if len(args) == 0 || args[0] == "status" {
		return showGeoIP()
	}
	if args[0] == "lookup" && len(args) == 2 {
		return showGeoIPLookup(args[1])
	}
	if args[0] == "import" && len(args) == 2 {
		data, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		out, err := call("POST", "/v1/geoip/import", data)
		if err != nil {
			return err
		}
		fmt.Println("imported; rules naming countries use it now")
		return printGeoIP(out)
	}
	return fmt.Errorf("usage: geoip [status] | lookup IP | import FILE")
}
