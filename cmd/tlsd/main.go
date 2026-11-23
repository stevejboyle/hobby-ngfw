// Command tlsd is SJB-OS's TLS decryption daemon. The ruleset hands it the
// TCP connections decryption rules cover (tproxy); it reads each client's
// TLS hello, decides whether to decrypt, and sends the connection's bytes
// (decrypted, or as they were) round the cleartext loop, a hop through the
// firewall's forward chain, so the security rules, App Identification and
// the IPS work on them. See internal/compiler/decrypt.go for the data path.
//
// ngfwd starts and stops it (sjb-tlsd.service), writes its policy file and
// reads its status over a Unix socket.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/stevejboyle/sjb-os/internal/compiler"
	"github.com/stevejboyle/sjb-os/internal/decrypt"
	"github.com/stevejboyle/sjb-os/internal/logs"
)

func main() {
	port := flag.Int("port", compiler.DecryptPort, "port the ruleset hands connections to (tproxy)")
	loopPort := flag.Int("loop-port", compiler.DecryptPort+1, "port of the loop's far end, in the server-half namespace")
	nsClient := flag.String("netns-client", "/run/netns/sjbd-c", "network namespace of the loop's client half")
	nsServer := flag.String("netns-server", "/run/netns/sjbd-s", "network namespace of the loop's server half")
	policyPath := flag.String("policy", decrypt.PolicyFile, "policy file ngfwd writes")
	caDir := flag.String("ca", decrypt.CADir, "decryption CA directory")
	builtin := flag.String("builtin", decrypt.BuiltinExclusionsFile, "SJB-OS's built-in exclusion list")
	learnedPath := flag.String("learned", "/var/lib/sjb-tlsd/learned.json", "learned (pinned) servers")
	maxActive := flag.Int64("max-conns", 4096, "connections held at once before tlsd reports itself busy (new ones then pass undecrypted)")
	statusSock := flag.String("status", "/run/sjb-tlsd/tlsd.sock", "status socket for ngfwd")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	leaf, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Error("no leaf key", "err", err)
		os.Exit(1)
	}
	// Debian's trusted roots (ca-certificates); SSL_CERT_FILE/SSL_CERT_DIR
	// add others (the boot test uses that for its own server).
	roots, err := x509.SystemCertPool()
	if err != nil {
		log.Error("no trusted roots: server certificates can't be checked", "err", err)
		os.Exit(1)
	}
	p := &proxy{
		now:  time.Now,
		emit: func(d logs.Decryption) { fmt.Println(d.Line()) },
		leaf: leaf, roots: roots,
		learned:  decrypt.OpenLearned(*learnedPath, decrypt.LearnedTTL),
		sessions: tls.NewLRUClientSessionCache(4096),
		dialLoop: func(ctx context.Context, client, server netip.AddrPort, dscp int) (net.Conn, error) {
			return dialLoop(ctx, *nsClient, client, server, dscp)
		},
		dialUp: func(ctx context.Context, server netip.AddrPort) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, "tcp4", server.String())
		},
		markOf:           socketMark,
		helloTimeout:     10 * time.Second,
		handshakeTimeout: 20 * time.Second,
	}
	load := func() {
		st := loadState(*policyPath, *caDir, *builtin)
		p.st.Store(st)
		p.certs.reset()
		if st.err != "" {
			log.Warn("policy or CA not loaded", "err", st.err)
		}
		log.Info("policy loaded", "mode", st.policy.Mode, "rules", len(st.policy.Rules), "exclusion_names", st.match.Len(), "ca", st.cas != nil)
	}
	load()

	ln, err := listenTransparent("", *port)
	if err != nil {
		log.Error("can't listen for handed-over connections", "port", *port, "err", err)
		os.Exit(1)
	}
	loop, err := listenTransparent(*nsServer, *loopPort)
	if err != nil {
		log.Error("can't listen at the loop's far end", "netns", *nsServer, "port", *loopPort, "err", err)
		os.Exit(1)
	}
	go p.serveLoop(loop)

	started := time.Now()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		st := p.st.Load()
		s := decrypt.Status{Mode: st.policy.Mode, Started: started, Rules: len(st.policy.Rules), Exclusions: st.match.Len(), Builtin: st.policy.Builtin,
			Counts: p.Counts(), Active: p.active.Load(), Learned: len(p.learned.List(p.now())), LoadError: st.err,
			MaxActive: *maxActive, Busy: p.active.Load() >= *maxActive}
		if st.cas != nil {
			s.CA = decrypt.InfoOf(*st.cas)
			s.CA.PEM = ""
		}
		writeJSON(w, s)
	})
	mux.HandleFunc("GET /v1/learned", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, p.learned.List(p.now())) })
	mux.HandleFunc("POST /v1/learned/clear", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]int{"cleared": p.learned.Clear(p.now())})
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, r *http.Request) {
		load()
		writeJSON(w, map[string]string{"status": "reloaded", "error": p.st.Load().err})
	})
	os.Remove(*statusSock)
	sl, err := net.Listen("unix", *statusSock)
	if err != nil {
		log.Error("no status socket", "err", err)
		os.Exit(1)
	}
	os.Chmod(*statusSock, 0o600)
	go (&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}).Serve(sl)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			load()
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Info("stopping; connections in progress end")
		ln.Close()
		loop.Close()
		os.Exit(0)
	}()

	log.Info("decrypting at the border", "port", *port, "loop_port", *loopPort)
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				select {} // stopping
			}
			log.Warn("accept", "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go p.handle(c)
	}
}

// loadState reads the policy, the exclusion lists and the CAs. A missing
// policy means observe nothing in particular (pass through); a missing CA
// means pass through everything.
func loadState(policyPath, caDir, builtinPath string) *state {
	st := &state{policy: decrypt.Policy{Mode: decrypt.ModeObserve}}
	var errs []string
	if p, err := decrypt.ReadPolicy(policyPath); err != nil {
		errs = append(errs, "policy: "+err.Error())
	} else {
		st.policy = p
	}
	lists := map[string][]string{}
	for _, e := range st.policy.Exclusions {
		lists[e.Name] = e.Domains
	}
	if st.policy.Builtin {
		if f, err := os.Open(builtinPath); err != nil {
			errs = append(errs, "built-in exclusions: "+err.Error())
		} else {
			lists["built-in"] = decrypt.ReadList(f)
			f.Close()
		}
	}
	st.match = decrypt.NewMatcher(lists)
	if cas, err := decrypt.LoadCAs(caDir); err == nil {
		st.cas = &cas
	} else if !os.IsNotExist(err) {
		errs = append(errs, "CA: "+err.Error())
	}
	if len(errs) > 0 {
		st.err = fmt.Sprint(errs)
	}
	return st
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
