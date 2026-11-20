package daemon

import (
	"testing"

	"github.com/stevejboyle/hobby-ngfw/internal/config"
	"github.com/stevejboyle/hobby-ngfw/internal/nicaddr"
)

func TestWantedNICsTrunk(t *testing.T) {
	cfg := &config.Config{
		System: config.System{MgmtInterface: "mgmt"},
		Interfaces: []config.Interface{
			{Name: "mgmt"},
			{Name: "inside"}, // trunk
			{Name: "inside.150", Zone: "inside", Address: "192.168.150.1/24"},
			{Name: "outside", Zone: "outside", Address: "192.168.149.254/24"},
		},
	}
	got := wantedNICs(cfg)
	if got["inside"] != nicaddr.TrunkOnly || got["outside"] != "192.168.149.254/24" || len(got) != 2 {
		t.Errorf("wantedNICs = %v", got)
	}
}
