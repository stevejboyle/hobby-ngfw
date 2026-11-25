package snmp

import (
	"fmt"
	"strings"

	"github.com/stevejboyle/sjb-os/internal/config"
)

// PassHelper is the pass_persist program for SJB-OS-MIB.
const PassHelper = "/usr/local/sbin/sjb-snmp-pass"

// Compile turns the config and credentials into snmpd.conf. It returns ""
// when SNMP is off. Every credential the config names must exist with the
// right kind (CheckRefs).
func Compile(cfg *config.Config, cs *Credentials) (string, error) {
	if cfg == nil || !cfg.SNMP.On() {
		return "", nil
	}
	if err := CheckRefs(cfg, cs); err != nil {
		return "", err
	}
	if cs.InternalPass == "" {
		return "", fmt.Errorf("snmp: no internal user passphrase")
	}
	s := cfg.SNMP
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	w("# SJB-OS SNMP agent: written by ngfwd from the running config. Don't edit:")
	w("# changes are overwritten at the next commit (set snmp ... in the CLI).")
	w("")
	w("# Listen on every address; the firewall's input chain keeps zoned")
	w("# interfaces out, and snmpd runs in the management VRF.")
	w("agentAddress udp:161")
	w("sysName %s", or(cfg.System.Hostname, "sjb-fw"))
	if s.Location != "" {
		w("sysLocation %s", s.Location)
	}
	if s.Contact != "" {
		w("sysContact %s", s.Contact)
	}
	w("sysServices 72")
	w("")
	w("# Read-only access.")
	for _, n := range s.V3Users {
		c, _ := cs.Get(n)
		w("createUser %s %s %q %s %q", c.Name, c.Auth, c.AuthPass, c.Priv, c.PrivPass)
		w("rouser -s usm %s priv", c.Name)
	}
	for _, n := range s.Communities {
		c, _ := cs.Get(n)
		for _, m := range s.Managers {
			p, _ := config.SNMPManagerPrefix(m)
			w("rocommunity %s %s", c.Community, p)
		}
	}
	w("")
	w("# snmpd's own queries (link and trigger monitors) use an internal user.")
	w("# net-snmp's internal queries can't encrypt, so it is auth-only, with")
	w("# a random passphrase that is never shown.")
	w("createUser %s SHA-256 %q", InternalUser, cs.InternalPass)
	w("rouser -s usm %s auth", InternalUser)
	w("iquerySecName %s", InternalUser)
	w("iqueryVersion 3")
	w("iquerySecLevel authNoPriv")
	w("agentSecName %s", InternalUser)
	w("")
	w("# SJB-OS-MIB (%s), served from ngfwd's monitoring snapshot.", Base)
	w("pass_persist %s %s", Base, PassHelper)
	w("")
	if len(cfg.SNMPTrapReceivers) > 0 {
		w("# Trap receivers.")
		for _, r := range cfg.SNMPTrapReceivers {
			c, _ := cs.Get(r.Credential)
			target := fmt.Sprintf("%s:%d", r.Address, r.PortOrDefault())
			switch c.Kind {
			case KindV3:
				// Informs wait for an answer: keep the wait short, since
				// snmpd answers no polls while it waits.
				inform := ""
				if r.Inform == "on" {
					inform = "-Ci -t 2 -r 1 "
				}
				w("trapsess %s-v 3 -u %s -l authPriv -a %s -A %q -x %s -X %q %s", inform, c.Name, c.Auth, c.AuthPass, c.Priv, c.PrivPass, target)
			case KindV2c:
				w("trap2sink %s %s", target, c.Community)
			}
		}
		w("")
		w("# Traps: link up/down, and SJB-OS's triggers (checked every 30 s).")
		w("linkUpDownNotifications yes")
		w("monitor -r 30 -o %s sjbServiceDown %s != 0", OIDServiceName, OIDServiceFault)
		w("monitor -r 30 -I sjbIpsEngineDown %s != 0", OIDIPSFault)
		w("monitor -r 30 -I -o %s sjbCommitFailed %s == 0", OIDCommitNote, OIDLastCommitOK)
	}
	return b.String(), nil
}

// CheckRefs checks that the credentials the config names exist with the
// right kind. An inform needs a v3 user.
func CheckRefs(cfg *config.Config, cs *Credentials) error {
	var errs []string
	kind := func(where, name, want string) (Credential, bool) {
		c, ok := cs.Get(name)
		switch {
		case !ok:
			errs = append(errs, fmt.Sprintf("%s: no SNMP credential %q (request snmp credential add %s ...)", where, name, name))
		case want != "" && c.Kind != want:
			errs = append(errs, fmt.Sprintf("%s: %q is a %s credential, not %s", where, name, c.Kind, want))
		}
		return c, ok
	}
	for _, n := range cfg.SNMP.V3Users {
		kind("snmp.v3_users", n, KindV3)
	}
	for _, n := range cfg.SNMP.Communities {
		kind("snmp.v2c_communities", n, KindV2c)
	}
	for i, r := range cfg.SNMPTrapReceivers {
		where := fmt.Sprintf("snmp_trap_receivers[%d] %q", i, r.Name)
		if c, ok := kind(where, r.Credential, ""); ok && r.Inform == "on" && c.Kind != KindV3 {
			errs = append(errs, fmt.Sprintf("%s: informs need a v3 credential", where))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// UsedBy says what in the config names a credential ("" when nothing).
func UsedBy(cfg *config.Config, name string) string {
	if cfg == nil {
		return ""
	}
	for _, n := range cfg.SNMP.V3Users {
		if n == name {
			return "snmp v3-users"
		}
	}
	for _, n := range cfg.SNMP.Communities {
		if n == name {
			return "snmp v2c-communities"
		}
	}
	for _, r := range cfg.SNMPTrapReceivers {
		if r.Credential == name {
			return fmt.Sprintf("snmp-trap-receiver %s", r.Name)
		}
	}
	return ""
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
