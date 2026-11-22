// Command ngfwd is the firewall daemon: commit pipeline, tag registry, the
// local management API on a Unix socket, and the optional network tag API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/accounts"
	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"github.com/stevejboyle/hobby-ngfw/internal/conntrack"
	"github.com/stevejboyle/hobby-ngfw/internal/daemon"
	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
	"github.com/stevejboyle/hobby-ngfw/internal/dhcp"
	"github.com/stevejboyle/hobby-ngfw/internal/frr"
	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/logfwd"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
	"github.com/stevejboyle/hobby-ngfw/internal/natips"
	"github.com/stevejboyle/hobby-ngfw/internal/netdev"
	"github.com/stevejboyle/hobby-ngfw/internal/nft"
	"github.com/stevejboyle/hobby-ngfw/internal/nicaddr"
	"github.com/stevejboyle/hobby-ngfw/internal/routes"
	"github.com/stevejboyle/hobby-ngfw/internal/stats"
	"github.com/stevejboyle/hobby-ngfw/internal/store"
	"github.com/stevejboyle/hobby-ngfw/internal/sysname"
	"github.com/stevejboyle/hobby-ngfw/internal/tags"
	"github.com/stevejboyle/hobby-ngfw/internal/upgrade"
	"github.com/stevejboyle/hobby-ngfw/internal/webui"
)

func main() {
	stateDir := flag.String("state", "/var/lib/ngfw", "state directory (revisions, tags)")
	socket := flag.String("socket", "/run/ngfw/ngfwd.sock", "management API Unix socket")
	socketGroup := flag.String("socket-group", "", "group allowed to use the management socket (the CLI's admins); empty = root only")
	apiListen := flag.String("api-listen", "", "address for the network tag API, e.g. :8443 (disabled if empty)")
	apiKeys := flag.String("api-keys", "/etc/ngfw/api-keys", "API key file for the network tag API")
	tlsCert := flag.String("tls-cert", "", "TLS certificate for the tag API (plain HTTP if empty)")
	tlsKey := flag.String("tls-key", "", "TLS key for the tag API")
	nftPath := flag.String("nft", "nft", "path to the nft binary")
	ctPath := flag.String("conntrack", "conntrack", "path to the conntrack binary (conntrack-tools)")
	flag.StringVar(&journalctlPath, "journalctl", "journalctl", "path to journalctl, which the Logs views read")
	flag.StringVar(&vtyshPath, "vtysh", "/usr/bin/vtysh", "path to vtysh")
	flag.StringVar(&frrDir, "frr", "/etc/frr", "FRR config directory (empty: don't manage BGP/OSPF, for development)")
	flag.StringVar(&appidStats, "appid-stats", appid.StatsPath, "appidd's statistics file")
	flag.StringVar(&decryptCA, "decryption-ca", decrypt.CADir, "decryption CA directory")
	flag.StringVar(&decryptPolicy, "decryption-policy", decrypt.PolicyFile, "where to write tlsd's policy (readable by tlsd's user)")
	flag.StringVar(&tlsdSocket, "tlsd-socket", "/run/sjb-tlsd/tlsd.sock", "tlsd's status socket")
	flag.StringVar(&tlsdPath, "tlsd", "/usr/local/sbin/tlsd", "tlsd, the TLS decryption daemon (empty: no decryption, for development)")
	flag.StringVar(&ipsDir, "ips-dir", "/var/lib/sjb-os/ips", "IPS signature directory (empty: no IPS, for development)")
	flag.StringVar(&keaPath, "kea", "/usr/sbin/kea-dhcp4", "path to kea-dhcp4, the DHCP server (empty: don't manage DHCP, for development)")
	flag.StringVar(&ipPath, "ip", "ip", "path to the ip binary for static routes (empty: don't manage routes, for development)")
	flag.StringVar(&hostnameDir, "hostname-dir", "", "apply system.hostname to the system: the hostname and hosts files in this directory, and the live hostname (the appliance passes /etc; empty: leave the hostname alone)")
	bootstrap := flag.String("bootstrap", "", "config file to commit as revision 1 if nothing has been committed yet")
	uiListen := flag.String("ui-listen", "", "address for the web UI, e.g. :443 (disabled if empty; needs -tls-cert)")
	webUsers := flag.String("web-users", "/etc/ngfw/web-users", "the web user file of versions before multiple users: imported once, then kept with admin's password for rollbacks")
	usersDB := flag.String("users", "/etc/ngfw/users.json", "user database (see fwctl web-passwd)")
	rolesDB := flag.String("roles", "/etc/ngfw/roles.json", "custom roles")
	unixAccounts := flag.Bool("unix-accounts", true, "manage each user's Unix login (SSH, console); off for development")
	root := flag.String("root", "/", "root filesystem for appliance upgrades")
	fwctlPath := flag.String("fwctl", "/usr/local/sbin/fwctl", "fwctl binary, used to run upgrades")
	uiDevHTTP := flag.Bool("ui-dev-http", false, "development only: serve the web UI over plain HTTP; refused unless -ui-listen is a loopback address")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgmtGroup = *socketGroup
	ui := uiOpts{listen: *uiListen, users: *webUsers, usersDB: *usersDB, rolesDB: *rolesDB, unixAccounts: *unixAccounts,
		root: *root, fwctl: *fwctlPath, devHTTP: *uiDevHTTP}
	if err := run(log, *stateDir, *socket, *apiListen, *apiKeys, *tlsCert, *tlsKey, *nftPath, *ctPath, *bootstrap, ui); err != nil {
		log.Error("ngfwd exiting", "err", err)
		os.Exit(1)
	}
}

type uiOpts struct {
	listen, users, usersDB, rolesDB, root, fwctl string
	devHTTP, unixAccounts                        bool
}

// installedVersion is the SJB-OS version for log messages ("" off the
// appliance).
func installedVersion() string {
	b, err := os.ReadFile("/etc/ngfw-version")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func run(log *slog.Logger, stateDir, socket, apiListen, apiKeys, tlsCert, tlsKey, nftPath, ctPath, bootstrap string, ui uiOpts) error {
	st, err := store.Open(stateDir)
	if err != nil {
		return err
	}
	reg, err := tags.Open(filepath.Join(stateDir, "tags.json"))
	if err != nil {
		return err
	}
	d := daemon.New(st, reg, nft.Exec{Path: nftPath}, conntrack.Exec{Path: ctPath}, log)
	if ipPath != "" {
		d.SetRouter(routes.Exec{Path: ipPath, RestoreDefault: restoreDeploymentDefault})
		d.SetNetdev(netdev.Exec{Path: ipPath})
		d.SetNATIPs(natips.Exec{Path: ipPath})
		d.SetNICs(&nicaddr.Networkd{Dir: "/etc/systemd/network", NICs: []string{"inside", "outside"}, HasAddr: nicaddr.IPHasAddr(ipPath)})
	}
	if hostnameDir != "" {
		d.SetHostname(&sysname.Host{Etc: hostnameDir, Get: os.Hostname, Set: setHostname})
	}
	if frrDir != "" {
		d.SetFRR(frr.Exec{Dir: frrDir, Vtysh: vtyshPath})
	}
	if keaPath != "" {
		d.SetDHCP(dhcp.Exec{Binary: keaPath})
	}
	// Dashboard statistics: a sample a minute, kept a week.
	if st, err := stats.Open(filepath.Join(stateDir, "stats", "samples.jsonl"), nil); err != nil {
		log.Warn("dashboard statistics off", "err", err)
	} else {
		d.SetStats(st, statsRoot)
		go func() {
			for range time.Tick(time.Minute) {
				if err := d.SampleStats(); err != nil {
					log.Warn("dashboard statistics sample", "err", err)
				}
			}
		}()
	}
	if ipsDir != "" {
		d.SetIPS(ips.Exec{Conntrack: ctPath}, &ips.Engine{Dir: ipsDir})
		// Suricata's alerts become threat log entries.
		if closeEVE, err := ips.Listen(ips.EVESocket, d.IPSAlert); err != nil {
			log.Warn("IPS alerts won't be logged", "socket", ips.EVESocket, "err", err)
		} else {
			defer closeEVE()
		}
		go d.RunIPSUpdates(context.Background())
	}
	if tlsdPath != "" {
		d.SetDecrypt(decrypt.Exec{Binary: tlsdPath, Socket: tlsdSocket}, decryptCA, decryptPolicy)
		go d.RunDecryptHealth(context.Background())
	}
	// Log forwarding to syslog servers (a SIEM): one journal follower,
	// started only while the running config has log servers.
	fwd := &logfwd.Forwarder{
		Journal:    logs.Journal{ZoneOf: d.ZoneOf, RuleName: d.RuleName},
		Source:     logfwd.Journalctl(journalctlPath),
		CursorFile: logfwd.CursorPath(stateDir),
		Version:    installedVersion(),
		Log:        log,
	}
	d.SetLogForwarder(fwd)
	defer fwd.Close()
	// Users and roles: one password per user for SSH, the console and the
	// web UI; every change goes to the Unix login and the user database
	// together.
	acct := &accounts.Store{Path: ui.usersDB, RolesPath: ui.rolesDB, Legacy: ui.users, Log: log}
	if ui.unixAccounts {
		acct.Sys = accounts.DefaultExec()
		if u, err := user.Lookup(accounts.Admin); err == nil && u.HomeDir != "" {
			acct.AdminKeys = filepath.Join(u.HomeDir, ".ssh", "authorized_keys")
		}
	}
	if err := acct.Open(); err != nil {
		return fmt.Errorf("user database: %w", err)
	}
	acct.Reconcile()
	d.SetAccounts(acct)
	if err := d.Start(); err != nil {
		return err
	}
	// Static routes can't go in before their interfaces are up (ngfwd starts
	// before networking), and networkd may drop them when it reconfigures a
	// link, so keep putting them back.
	go func() {
		for range time.Tick(10 * time.Second) {
			d.ReconcileRoutes()
		}
	}()
	if bootstrap != "" {
		if n, _, err := st.Running(); err == nil && n == 0 {
			data, err := os.ReadFile(bootstrap)
			if err != nil {
				return err
			}
			if err := d.SetCandidate(data); err != nil {
				return err
			}
			res, err := d.Commit("bootstrap", "initial config from "+bootstrap, 0)
			if err != nil {
				return err
			}
			log.Info("bootstrap config committed", "revision", res.Revision.N, "warnings", res.Warnings)
		}
	}

	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return err
	}
	os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		return err
	}
	if mgmtGroup != "" {
		if err := shareSocket(socket, mgmtGroup); err != nil {
			log.Warn("management socket stays root-only", "group", mgmtGroup, "err", err)
		} else {
			log.Info("management socket shared with group", "group", mgmtGroup)
		}
	}
	d.SetAppID(appid.Source{StatsFile: appidStats})
	logReader := logs.Journal{Path: journalctlPath, ZoneOf: d.ZoneOf, RuleName: d.RuleName}
	d.SetLogs(logReader)
	d.SetAPIKeysFile(apiKeys)
	mgmt := http.NewServeMux()
	mgmt.Handle("/", d.MgmtHandler())
	// The caller is the socket peer's Unix user, as the kernel reports it.
	servers := []*http.Server{{Handler: mgmt, ReadHeaderTimeout: 10 * time.Second,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return daemon.WithCaller(ctx, socketCaller(c))
		}}}
	errc := make(chan error, 3)
	go func() { errc <- servers[0].Serve(ln) }()
	log.Info("management API listening", "socket", socket)

	if apiListen != "" {
		keys, err := daemon.LoadKeys(apiKeys)
		if err != nil {
			return err
		}
		api := &http.Server{Addr: apiListen, Handler: d.APIHandler(keys), ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, api)
		go func() {
			if tlsCert != "" {
				errc <- api.ListenAndServeTLS(tlsCert, tlsKey)
			} else {
				log.Warn("tag API is plain HTTP; use -tls-cert/-tls-key outside the lab")
				errc <- api.ListenAndServe()
			}
		}()
		log.Info("tag API listening", "addr", apiListen, "keys", len(keys))
	}

	if ui.listen != "" {
		if ui.devHTTP {
			host, _, err := net.SplitHostPort(ui.listen)
			if ip, perr := netip.ParseAddr(host); err != nil || perr != nil || !ip.IsLoopback() {
				return errors.New("-ui-dev-http only works with a loopback -ui-listen address, e.g. 127.0.0.1:9443")
			}
		} else if tlsCert == "" {
			return errors.New("-ui-listen needs -tls-cert and -tls-key: the web UI is HTTPS only")
		}
		h := webui.New(d, webui.Options{
			Logs: logReader,
			Upgrader: &webui.SystemdUpgrader{
				Installer: &upgrade.Installer{Root: ui.root},
				Fwctl:     ui.fwctl,
			},
			Log: log,
		})
		srv := &http.Server{Addr: ui.listen, Handler: h, ReadHeaderTimeout: 10 * time.Second}
		servers = append(servers, srv)
		go func() {
			if ui.devHTTP {
				log.Warn("web UI on plain HTTP for development")
				errc <- srv.ListenAndServe()
				return
			}
			errc <- srv.ListenAndServeTLS(tlsCert, tlsKey)
		}()
		log.Info("web UI listening", "addr", ui.listen)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Info("shutting down", "signal", s.String())
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(ctx)
	}
	return nil
}

// socketCaller names the management socket's caller from its Unix user:
// root is root (a superuser, for recovery); anyone else is the SJB-OS user
// of the same name, and the user database decides what they may do.
func socketCaller(c net.Conn) accounts.Caller {
	uid, err := peerUID(c)
	if err != nil {
		return accounts.Caller{Name: "unknown", Via: "cli"}
	}
	if uid == 0 {
		return accounts.Root
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return accounts.Caller{Name: "uid-" + strconv.Itoa(uid), Via: "cli"}
	}
	if runtime.GOOS != "linux" {
		// Development: the user running ngfwd (see peerUID).
		return accounts.Caller{Name: u.Username, Via: "root"}
	}
	return accounts.Caller{Name: u.Username, Via: "cli"}
}

// mgmtGroup may use the management socket (set by -socket-group).
var mgmtGroup string

// ipPath is the ip binary for static routes (set by -ip).
var ipPath string

// hostnameDir is where the hostname and hosts files are (/etc on the
// appliance); empty leaves the hostname alone.
var hostnameDir string

// frrDir is FRR's config directory (set by -frr); vtyshPath its shell.
var frrDir, vtyshPath string

// keaPath is the DHCP server binary ("" = DHCP not managed).
var keaPath string

// ipsDir holds the IPS signatures; empty: no IPS (development).
var ipsDir string

// tlsdPath is the TLS decryption daemon; empty: no decryption (development).
var tlsdPath, tlsdSocket, decryptCA, decryptPolicy string

// statsRoot is where interface counters are read (/sys under it).
var statsRoot = "/"

// appidStats is appidd's statistics file (set by -appid-stats).
var appidStats string

// journalctlPath reads the traffic and system logs (set by -journalctl).
var journalctlPath string

// shareSocket lets members of group use the socket: the directory and socket
// become group-owned, 0750 and 0660. The group is created by sjb-migrate.
func shareSocket(socket, group string) error {
	g, err := user.LookupGroup(group)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return err
	}
	dir := filepath.Dir(socket)
	for _, p := range []struct {
		path string
		mode os.FileMode
	}{{dir, 0o750}, {socket, 0o660}} {
		if err := os.Chown(p.path, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(p.path, p.mode); err != nil {
			return err
		}
	}
	return nil
}

// restoreDeploymentDefault has systemd-networkd re-apply the outside
// interface's deployment settings, which puts its default route back after a
// configured default route that had replaced it is removed. When the config
// sets outside's address, ngfwd's override is in charge and has no gateway:
// there is nothing to restore, and a reconfigure would only take the address
// down while conflict detection runs again.
func restoreDeploymentDefault() error {
	if nicaddr.HasOverride("/etc/systemd/network", "outside") {
		return nil
	}
	out, err := exec.Command("networkctl", "reconfigure", "outside").CombinedOutput()
	if err != nil {
		return fmt.Errorf("networkctl reconfigure outside: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
