package logs

import (
	"strings"
	"testing"
)

// testGeo: 93.184.216.34 in US/AS15133, 1.1.1.1 in AU/AS13335, a threat's
// 203.0.113.9 in CN/AS4134; everything else unknown.
func testGeo(addr string) (string, uint32, string) {
	switch addr {
	case "93.184.216.34":
		return "US", 15133, "Edgecast Inc."
	case "1.1.1.1":
		return "AU", 13335, "Cloudflare, Inc."
	case "203.0.113.9":
		return "CN", 4134, "Chinanet"
	}
	return "", 0, ""
}

func TestTrafficGeo(t *testing.T) {
	var args []string
	j := fake(kernel, &args)
	j.Geo = testGeo
	tr, err := j.Traffic(10, "")
	if err != nil || len(tr) != 2 {
		t.Fatalf("%v %+v", err, tr)
	}
	icmp, web := tr[0], tr[1]
	if icmp.DstCountry != "AU" || icmp.DstASN != 13335 || icmp.SrcCountry != "" || icmp.SrcASN != 0 {
		t.Errorf("icmp geo %+v", icmp.Geo)
	}
	if web.Value("dst_country") != "US" || web.Value("dst_asn") != "AS15133 Edgecast Inc." || web.Value("src_asn") != "" {
		t.Errorf("columns: %q %q %q", web.Value("dst_country"), web.Value("dst_asn"), web.Value("src_asn"))
	}
	for q, want := range map[string]int{
		"dst_country = au":                     1,
		"country = US":                         1,
		"src_country = US":                     0,
		"country != US":                        1,
		"asn = 15133":                          1,
		"dst_asn >= 13335":                     2,
		"src_asn = 15133":                      0,
		"org ~ cloudflare":                     1,
		"dst_org ~ edgecast":                   1,
		"Edgecast":                             1, // bare words see the AS too
		"dst_country = AU or dst_country = US": 2,
	} {
		got, err := j.Traffic(10, q)
		if err != nil {
			t.Errorf("%q: %v", q, err)
			continue
		}
		if len(got) != want {
			t.Errorf("%q: %d entries, want %d", q, len(got), want)
		}
	}
	// No lookup: the fields stay empty and queries on them match nothing.
	plain := fake(kernel, &args)
	if tr, _ := plain.Traffic(10, "country = US"); len(tr) != 0 {
		t.Errorf("no geo: %+v", tr)
	}
}

func TestRecordGeo(t *testing.T) {
	j := Journal{Geo: testGeo}
	// A threat line that claims geo fields of its own: the lookup replaces them.
	line := `{"__CURSOR":"c3","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"ngfwd.service","MESSAGE":"ngfw-threat {\"rule\":\"web-out\",\"sid\":9900001,\"src\":\"10.0.0.5\",\"dst\":\"203.0.113.9\",\"proto\":\"tcp\",\"src_country\":\"XX\"}"}`
	r, ok := j.ParseRecord([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	th := r.Entry.(Threat)
	if th.SrcCountry != "" || th.DstCountry != "CN" || th.DstASN != 4134 {
		t.Errorf("threat geo %+v", th.Geo)
	}
	if js := toJSON(th); !strings.Contains(js, `"dst_country":"CN","dst_asn":4134,"dst_as_org":"Chinanet"`) || strings.Contains(js, "src_country") {
		t.Errorf("json %s", js)
	}
	line = `{"__CURSOR":"c4","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"sjb-tlsd.service","MESSAGE":"ngfw-decrypt {\"rule\":\"d1\",\"decision\":\"decrypted\",\"src\":\"10.0.0.5\",\"dst\":\"1.1.1.1\"}"}`
	if r, _ := j.ParseRecord([]byte(line)); r.Entry.(Decryption).DstASN != 13335 {
		t.Errorf("decryption geo %+v", r.Entry)
	}
	line = `{"__CURSOR":"c1","__REALTIME_TIMESTAMP":"1763700000000000","_TRANSPORT":"kernel","MESSAGE":"ngfw web-out allow IN=inside OUT=outside SRC=10.0.0.5 DST=93.184.216.34 LEN=60 TTL=64 PROTO=TCP SPT=40000 DPT=443 SYN"}`
	if r, _ := j.ParseRecord([]byte(line)); r.Entry.(Traffic).DstCountry != "US" {
		t.Errorf("traffic geo %+v", r.Entry)
	}
	line = `{"__CURSOR":"c2","__REALTIME_TIMESTAMP":"1763700000000000","_SYSTEMD_UNIT":"appidd.service","MESSAGE":"ngfw-session rule=3 app=YouTube cat=Media proto=tcp src=10.0.0.5 sport=40000 dst=1.1.1.1 dport=443 bytes=900 packets=9 dur=1.5"}`
	if r, _ := j.ParseRecord([]byte(line)); r.Entry.(Traffic).DstCountry != "AU" {
		t.Errorf("session geo %+v", r.Entry)
	}
}

func TestGeoColumnsAndSchemas(t *testing.T) {
	for name, cols := range map[string][]Column{"traffic": TrafficColumns, "threat": ThreatColumns, "decryption": DecryptionColumns} {
		var names []string
		for _, c := range cols {
			names = append(names, c.Name)
		}
		s := strings.Join(names, " ")
		if !strings.Contains(s, "sport src_country src_asn") || !strings.Contains(s, "dport dst_country dst_asn") {
			t.Errorf("%s columns: %s", name, s)
		}
	}
	for name, def := range map[string][]string{"traffic": DefaultTrafficColumns, "threat": DefaultThreatColumns, "decryption": DefaultDecryptionColumns} {
		s := strings.Join(def, " ")
		if !strings.Contains(s, "src_country") || !strings.Contains(s, "dst_country") || strings.Contains(s, "_asn") {
			t.Errorf("%s defaults: %s", name, s)
		}
	}
	for name, sc := range map[string]Schema{"traffic": TrafficSchema, "threat": ThreatSchema, "decryption": DecryptionSchema} {
		for _, f := range []string{"src_country", "dst_country", "country", "src_asn", "dst_asn", "asn", "src_org", "dst_org", "org"} {
			if _, ok := sc[f]; !ok {
				t.Errorf("%s schema lacks %s", name, f)
			}
		}
	}
	if ASText(0, "x") != "" || ASText(15169, "") != "AS15169" || ASText(15169, "Google LLC") != "AS15169 Google LLC" {
		t.Error("ASText")
	}
}
