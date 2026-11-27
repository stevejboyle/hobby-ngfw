package logs

import "strconv"

// Geo is where an entry's addresses are: the country and autonomous system
// of the source and of the destination. ngfwd looks them up when the entry
// is read or forwarded (Journal.Geo), from the databases in use then, so
// an old entry read after a monthly refresh shows the newer data.
type Geo struct {
	SrcCountry string `json:"src_country,omitempty"`
	SrcASN     uint32 `json:"src_asn,omitempty"`
	SrcASOrg   string `json:"src_as_org,omitempty"`
	DstCountry string `json:"dst_country,omitempty"`
	DstASN     uint32 `json:"dst_asn,omitempty"`
	DstASOrg   string `json:"dst_as_org,omitempty"`
}

// GeoFunc returns the country (ISO code) and AS of an address; "" and 0
// when unknown (private and reserved ranges, IPv6, no database).
type GeoFunc func(addr string) (country string, asn uint32, org string)

// fill sets g from f for src and dst, replacing whatever g held (a journal
// line never supplies these). A nil f leaves g empty.
func (g *Geo) fill(f GeoFunc, src, dst string) {
	*g = Geo{}
	if f == nil {
		return
	}
	g.SrcCountry, g.SrcASN, g.SrcASOrg = f(src)
	g.DstCountry, g.DstASN, g.DstASOrg = f(dst)
}

// ASText is an AS as the logs show it: "AS15169 Google LLC".
func ASText(asn uint32, org string) string {
	if asn == 0 {
		return ""
	}
	s := "AS" + strconv.FormatUint(uint64(asn), 10)
	if org != "" {
		s += " " + org
	}
	return s
}

// value is a geo column's text; ok is false for other columns. Besides the
// display columns, src_asnum/dst_asnum (the number alone) and
// src_org/dst_org serve queries.
func (g Geo) value(col string) (string, bool) {
	num := func(n uint32) string {
		if n == 0 {
			return ""
		}
		return strconv.FormatUint(uint64(n), 10)
	}
	switch col {
	case "src_country":
		return g.SrcCountry, true
	case "dst_country":
		return g.DstCountry, true
	case "src_asn":
		return ASText(g.SrcASN, g.SrcASOrg), true
	case "dst_asn":
		return ASText(g.DstASN, g.DstASOrg), true
	case "src_asnum":
		return num(g.SrcASN), true
	case "dst_asnum":
		return num(g.DstASN), true
	case "src_org":
		return g.SrcASOrg, true
	case "dst_org":
		return g.DstASOrg, true
	}
	return "", false
}

// geoSchema are the query fields every log with addresses gets.
var geoSchema = Schema{
	"src_country": {kText, []string{"src_country"}, "source country, e.g. src_country = CN"},
	"dst_country": {kText, []string{"dst_country"}, "destination country"},
	"country":     {kText, []string{"src_country", "dst_country"}, "either country"},
	"src_asn":     {kNum, []string{"src_asnum"}, "source AS number, e.g. src_asn = 15169"},
	"dst_asn":     {kNum, []string{"dst_asnum"}, "destination AS number"},
	"asn":         {kNum, []string{"src_asnum", "dst_asnum"}, "either AS number"},
	"src_org":     {kText, []string{"src_org"}, "source AS organisation, e.g. src_org ~ google"},
	"dst_org":     {kText, []string{"dst_org"}, "destination AS organisation"},
	"org":         {kText, []string{"src_org", "dst_org"}, "either AS organisation"},
}

// withGeo returns s plus the geo query fields.
func withGeo(s Schema) Schema {
	for k, v := range geoSchema {
		s[k] = v
	}
	return s
}
