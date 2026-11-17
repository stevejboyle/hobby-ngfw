// Command ngfwd is the firewall daemon: commit pipeline, tag registry, the
// local management API on a Unix socket, and the optional network tag API.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stevejboyle/hobby-ngfw/internal/appid"
	"github.com/stevejboyle/hobby-ngfw/internal/conntrack"
	"github.com/stevejboyle/hobby-ngfw/internal/daemon"
	"github.com/stevejboyle/hobby-ngfw/internal/decrypt"
	"github.com/stevejboyle/hobby-ngfw/internal/dhcp"
	"github.com/stevejboyle/hobby-ngfw/internal/frr"
	"github.com/stevejboyle/hobby-ngfw/internal/ips"
	"github.com/stevejboyle/hobby-ngfw/internal/logs"
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
	webUsers := flag.String("web-users", "/etc/ngfw/web-users", "web UI user file (see fwctl web-passwd)")
	root := flag.String("root", "/", "root filesystem for appliance upgrades")
	fwctlPath := flag.String("fwctl", "/usr/local/sbin/fwctl", "fwctl binary, used to run upgrades")
	uiDevHTTP := flag.Bool("ui-dev-http", false, "development only: serve the web UI over plain HTTP; refused unless -ui-listen is a loopback address")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	mgmtGroup = *socketGroup
	ui := uiOpts{listen: *uiListen, users: *webUsers, root: *root, fwctl: *fwctlPath, devHTTP: *uiDevHTTP}
	if err := run(log, *stateDir, *socket, *apiListen, *apiKeys, *tlsCert, *tlsKey, *nftPath, *ctPath, *bootstrap, ui); err != nil {
		log.Error("ngfwd exiting", "err", err)
		os.Exit(1)
	}
}

type uiOpts struct {
	listen, users, root, fwctl string
	devHTTP                    bool
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
	// One password for admin everywhere: changes go to the web user file
	// and the Unix account (SSH, console) together.
	users := &webui.Users{Path: ui.users, System: webui.SetUnixPassword}
	d.SetAppID(appid.Source{StatsFile: appidStats})
	logReader := logs.Journal{Path: journalctlPath, ZoneOf: d.ZoneOf, RuleName: d.RuleName}
	mgmt := http.NewServeMux()
	mgmt.HandleFunc("GET /v1/logs/{kind}", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		q := r.URL.Query().Get("q")
		var v any
		var err error
		switch r.PathValue("kind") {
		case "traffic":
			v, err = logReader.Traffic(n, q)
		case "system":
			v, err = logReader.System(n, q)
		case "threat":
			v, err = logReader.Threat(n, q)
		case "decryption":
			v, err = logReader.Decryption(n, q)
		default:
			http.Error(w, `{"error":"logs are traffic, threat, decryption or system"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, logs.ErrQuery) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		json.NewEncoder(w).Encode(v)
	})
	// The CLI's passwd: the caller proves the current password.
	mgmt.HandleFunc("POST /v1/password", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			User    string `json:"user"`
			Current string `json:"current"`
			New     string `json:"new"`
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "bad JSON"})
			return
		}
		if !users.Verify(req.User, req.Current) {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "current password is wrong"})
			return
		}
		if err := users.Set(req.User, req.New); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}
		log.Info("password changed from the CLI", "user", req.User)
		json.NewEncoder(w).Encode(map[string]string{"status": "password changed"})
	})
	mgmt.Handle("/", d.MgmtHandler())
	// The tag API keys file is root-only; CLI admins read it through here.
	mgmt.HandleFunc("GET /v1/api-keys", func(w http.ResponseWriter, r *http.Request) {
		data, err := os.ReadFile(apiKeys)
		if err != nil {
			http.Error(w, `{"error":"no tag API key file"}`, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	})
	servers := []*http.Server{{Handler: mgmt, ReadHeaderTimeout: 10 * time.Second}}
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
			Users: users,
			Logs:  logReader,
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
