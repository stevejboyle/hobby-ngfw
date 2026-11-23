package daemon

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/stevejboyle/sjb-os/internal/mgmtcert"
)

// certNames is what the management certificate should cover, from the
// running config.
type certNames struct{ hostname, mgmt string }

var errNoMgmtCert = errors.New("the management certificate is not managed here (ngfwd runs without -tls-cert)")

// SetMgmtCert has the daemon manage the web UI's and tag API's
// certificate. Call before Start.
func (d *Daemon) SetMgmtCert(m *mgmtcert.Manager) { d.mgmtCert = m }

// MgmtCertNames is what the certificate should name: the hostname and the
// management interface's addresses (configured or from the deployment).
func (d *Daemon) MgmtCertNames() mgmtcert.Names {
	n := mgmtcert.Names{}
	mgmt := "mgmt"
	if c := d.certNames.Load(); c != nil {
		n.Hostname = c.hostname
		if c.mgmt != "" {
			mgmt = c.mgmt
		}
	}
	if n.Hostname == "" {
		n.Hostname, _ = os.Hostname()
	}
	if ifc, err := net.InterfaceByName(mgmt); err == nil {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Is4() {
				n.IPs = append(n.IPs, p.Addr())
			}
		}
	}
	return n
}

// MgmtCert describes the management certificate.
func (d *Daemon) MgmtCert() (mgmtcert.Info, error) {
	if d.mgmtCert == nil {
		return mgmtcert.Info{}, errNoMgmtCert
	}
	return d.mgmtCert.Info(d.MgmtCertNames())
}

// ImportMgmtCert installs the operator's certificate, chain and key. New
// connections to the web UI and the tag API get it at once; open ones
// (the importer's included) keep the old one until they reconnect.
func (d *Daemon) ImportMgmtCert(author string, cert, key []byte) (mgmtcert.Info, error) {
	if d.mgmtCert == nil {
		return mgmtcert.Info{}, errNoMgmtCert
	}
	info, err := d.mgmtCert.Import(cert, key, d.MgmtCertNames())
	if err != nil {
		return mgmtcert.Info{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	d.log.Info("management certificate imported", "author", author, "subject", info.Subject, "issuer", info.Issuer, "fingerprint", info.Fingerprint)
	return info, nil
}

// ResetMgmtCert replaces the management certificate with a fresh
// self-signed one.
func (d *Daemon) ResetMgmtCert(author string) (mgmtcert.Info, error) {
	if d.mgmtCert == nil {
		return mgmtcert.Info{}, errNoMgmtCert
	}
	info, err := d.mgmtCert.SelfSigned(d.MgmtCertNames())
	if err != nil {
		return mgmtcert.Info{}, err
	}
	d.log.Info("management certificate back to self-signed", "author", author, "fingerprint", info.Fingerprint)
	return info, nil
}
