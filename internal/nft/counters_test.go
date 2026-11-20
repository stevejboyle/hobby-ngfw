package nft

import "testing"

func TestParseCounters(t *testing.T) {
	data := []byte(`{"nftables": [{"metainfo": {"version": "1.0.9"}},
 {"chain": {"family": "inet", "table": "ngfw", "name": "prerouting_nat"}},
 {"rule": {"chain": "prerouting_nat", "comment": "nat:web", "expr": [{"match": {}}, {"counter": {"packets": 3, "bytes": 180}}, {"dnat": {}}]}},
 {"rule": {"chain": "prerouting_nat", "comment": "nat:web", "expr": [{"counter": {"packets": 2, "bytes": 120}}]}},
 {"rule": {"chain": "prerouting_nat", "expr": [{"counter": {"packets": 9, "bytes": 9}}]}}]}`)
	got, err := ParseCounters(data)
	if err != nil {
		t.Fatal(err)
	}
	if c := got["nat:web"]; c.Packets != 5 || c.Bytes != 300 || len(got) != 1 {
		t.Errorf("got %+v", got)
	}
}
