# CLAUDE.md

Context for Claude Code sessions in this repo. Read docs/architecture.md for
the full design.

## What this is

An experimental firewall appliance on Debian + nftables, built without manual
coding (Claude Code under Steve's direction, reviewed with ChatGPT's help) to
demonstrate how far AI-assisted development goes. For isolated lab use; not a
commercial, supported or production-ready security product, and docs must
never imply otherwise or compare it to commercial products.
Single owner, public repo (Apache-2.0), not a supported product. History
before 0.9.9 lives in a private archive repo; don't reference old commits.

## Deployment model

The VMware OVA (deploy/appliance) is the only way anyone runs this. Assume
every user deploys the OVA on ESXi/vCenter with three networks (mgmt, inside,
outside) and manages it over SSH and the tag API on mgmt.

- User-facing docs describe the appliance only: no instructions for running
  ngfwd on a hand-built host, a laptop or a container.
- Interface names on the appliance are always `mgmt`, `inside`, `outside`;
  paths are `/etc/ngfw` (keys, TLS, initial config) and `/var/lib/ngfw`
  (revisions, tags). Features must work within that layout.
- Anything a feature needs at runtime (packages, units, sysctls, files) goes
  into the image via deploy/appliance, and the boot test checks it.
- The namespace lab and the container gate exist only to test the code in CI
  and during development. They are not a deployment path.
- The operator guide is deploy/appliance/README.md. Update it with any
  user-visible change.
- New config fields need an entry in `internal/cliconf/schema.go` so
  configure mode can set them and Tab can complete them.
- Anything the CLI can do, the web UI should be able to do, and the other
  way round. UI JSON calls go through the same `Daemon` methods as fwctl.
- Upgrade bundles may only write the paths in `internal/upgrade`'s allow
  list (binaries, units, scripts, /usr/share/sjb-os, the version file).
  Never config, state, secrets or first-boot network settings. Any new file
  the image installs from this repo must sit under an allowed path, or
  upgrades can't deliver it.
- Operators never get a Unix shell. `admin`'s SSH and console logins land in
  the captive CLI (`fwctl shell`, entered through `sjb-cli`); new operator
  features need a CLI command (and a web UI page). No sudo for `admin`; it
  reaches ngfwd through the management socket, shared with group `sjbadm`.
  CLI commands never pass input to a shell and run only fixed tools with
  checked arguments.
- Root: only what the operator sets at deploy time: `root_ssh_key` (SSH,
  key only, written by first boot to `/etc/ngfw/root_authorized_keys`,
  which upgrades never touch) and `root_password` (VMware console only).
  No root key or password ships in any image or bundle; build-image.sh
  fails a release image that has one. Steve's lab images may carry his key
  via `ROOT_KEY_FILE` (never published). Appliances from before 0.9.9 had
  the key in `usr/share/sjb-os/root-keys`; sjb-migrate moves it to /etc/ngfw
  and puts it back on rollback. The signing key (`upgrade-keys/*.pub`) is
  unrelated and stays: it lets appliances verify bundles, nothing more.
  boot-test.sh passes a throwaway root key and password through QEMU
  `-fw_cfg opt/sjb/<key>` (first boot reads it like guestinfo).
- `admin` has one password for SSH, the console and the web UI. Every change
  path (web UI, CLI `passwd` via ngfwd's `/v1/password`, root's
  `fwctl web-passwd`) goes through `webui.Users` with `System` set, which
  runs chpasswd before writing the web hash. Keep it that way.
- Debian packages ship inside bundles as files under
  /usr/share/sjb-os/packages (build.sh + fetch-packages.sh work out what
  the base image lacks; sjb-packages installs missing-or-older ones in the
  background, never downgrading). To add a package, add it to PACKAGES.
- VRF interfaces: netfilter's forward and input hooks see the VRF device as
  iif. The compiler matches interfaces in a VRF with `meta sdifname`, and in
  NAT postrouting (no sdif there) by a per-interface mark set in the raw
  prerouting chain. Keep both forms whenever interfaces are matched.
- Accounts, groups and shells can't ship as bundle files, so
  `sjb-migrate` (run by ngfwd.service after each start) sets them up
  idempotently, and `sjb-migrate undo` runs before any rollback. Put
  future one-time system changes there, with an undo.
- Version order (internal/upgrade/version.go): `X.Y.Z-rNN` revisions come
  after `X.Y.Z` (= r00) and compare numerically; other suffixes are
  pre-releases before it. Version checks run in the installed version's
  code, so changes to the ordering only take effect from the build after the
  one that ships them.
- The release signing key lives at `~/.config/sjb-os/upgrade-signing.key`
  on Steve's machine, never in the repo. The image trusts
  `rootfs/usr/share/sjb-os/upgrade-keys/*.pub`.
- Target vSphere 8.0 U1+: OVF virtual hardware `vmx-20`, guest type
  `debian12_64Guest`. The build validates the OVF against the DMTF OVF 1.1
  schema; keep it passing.

## SJB-OS branding

The appliance is SJB-OS, "Stops Junk at the Border", an SJB Consulting
product: login user `admin`, default hostname `sjb-fw`, the SJB logo
(navy #15212F, copper #C2884A; `internal/webui/static/favicon.svg`) in the web
UI, an ASCII mark on the console, an `X-SJB-OS` response header, and light
border-guard humour (sayings.txt, `fwctl sjb`, page taglines). Keep humour in
human-facing text only (banners, MOTD, CLI prose, log messages); never
change machine-readable output for it (JSON fields, the tag API's XML responses,
exit codes, nft comments, log prefixes). No third-party characters,
catchphrases or trademarks. Never name another firewall vendor, its products or its
feature trademarks anywhere: code, comments, tests, UI, docs, release notes,
commit messages. Application identification is "App Identification" in human
text, and its CLI keyword is `app-identification` (the YAML key `app_id` and
internal names such as `appidd` stay);
the XML tag endpoint is "XML user-ID messages". The repo is Apache-2.0: LICENSE, NOTICE and
THIRD_PARTY_NOTICES.md ship in /usr/share/sjb-os/licenses; list any new
third-party component there. Internal names (`ngfwd`, `fwctl`, `/etc/ngfw`,
`guestinfo.ngfw.*`) stay as they are.

Bundles install on 0.8.0 or newer (MIN_FROM); support for upgrading
appliances from before 0.8.0 was removed in 0.9.9-r03. Upgrade keys load
from files in today's format only; other lines in the key directory are
skipped.

## Architecture in one paragraph

`ngfwd` holds candidate/running config, validates, compiles it into one
nftables ruleset, and applies it atomically (`nft -f`) with rollback and
commit-confirmed. Only the nftables step is atomic: a commit records the
revision (and any confirmation deadline) first, applies, then sets running,
undoing earlier steps on failure (recovery state in Status if it can't);
FRR, Kea, the IPS and interfaces converge afterwards with warnings. Its tag registry
maps tags to IPs by writing nftables set elements with timeouts; tag and EDL
changes never touch the ruleset, so they need no commit. One mutex in
`internal/daemon` serialises every kernel change. Later: `appidd` (C, nDPI,
NFQUEUE) classifies flows into a conntrack label that rules match on;
Suricata runs inline on NFQUEUE; `logd` ships conntrack events and eve.json to
ClickHouse.

Phase 1 deliberately simplified the design doc: configd and tagd are one
process (`ngfwd`), revisions are files not SQLite, the management API is
HTTP/JSON on a root-only Unix socket rather than gRPC, and nftables is driven
through the `nft` binary rather than netlink. Revisit only if one of these
becomes a real limit.

## Layout

```
cmd/ngfwd/          daemon: commit pipeline, tag registry, APIs
cmd/fwctl/          CLI (offline validate/compile; everything else via ngfwd)
internal/config/    config schema types, loading, validation
internal/compiler/  config -> nftables ruleset; golden files in testdata/
internal/daemon/    commit/rollback/confirm, tag ops, mgmt + tag API handlers
internal/store/     candidate and numbered revisions on disk
internal/tags/      tag -> IP registry with TTL, persisted to JSON
internal/nft/       nft -f runner (and a fake for tests)
internal/conntrack/ conntrack flushes so policy changes hit existing flows
internal/diff/      line diff for `fwctl diff`
internal/netdev/    VRF devices (vrf-<name>) and VLAN subinterfaces (parent.id):
                    created at commit, re-synced every 10 s; owns only those
                    (never mgmt/inside/outside/vrf-mgmt)
internal/frr/       BGP/OSPF: config -> frr.conf (goldens in testdata/, CI runs
                    vtysh -C on them), apply with reload, status readers
internal/dhcp/      DHCP server: config -> Kea kea-dhcp4.conf (golden in testdata/,
                    CI runs kea-dhcp4 -t on the *-check.conf), apply via systemd,
                    leases over Kea's control socket
appidd/             App Identification daemon (C, nDPI 6.0 built by deploy/appliance/build-appidd.sh):
                    NFQUEUE first packets -> app ID in the ct mark (bits 0-10,
                    done 12; rules put their position+1 in bits 16-31, bit 11 =
                    log the session end), conntrack DESTROY -> /run/appidd/stats.json
                    and "ngfw-session" journal lines
internal/appid/     reads appidd's catalog and stats for show app / the Applications page
internal/ips/       IPS: ET Open download (md5-checked) and processing (every rule
                    alert + nfq_set_mark by severity, test sigs 9900001-4), status,
                    EVE alert socket; Suricata itself runs as sjb-ips.service
internal/routes/    static routes: sync the config's routes into the kernel
                    (`ip route ... proto 222`; ngfwd owns only proto 222)
cmd/fwctl/shell.go  the captive CLI (`fwctl shell`): operational and configure mode
internal/cliconf/   configure mode: schema of objects/attributes, set/delete/
                    move/rename on a working copy, Tab/? completion data
internal/lineedit/  the CLI's line editor (raw mode via stty, Tab, ?, history)
internal/logs/      traffic (kernel "ngfw <rule> <action>" lines) and system
                    (ngfwd/sshd/upgrade) logs, read from the journal
internal/upgrade/   signed upgrade bundles: build, verify, apply, auto-restore,
                    rollback (run by `fwctl upgrade`; a rollback re-commits
                    the config running at the upgrade if it changed since)
internal/webui/     web UI: session auth, JSON API under /ui/api/, embedded
                    static pages (plain JS/CSS in static/, no build step)
cmd/sjbpkg/       build machine tool: signing key, build and verify bundles
examples/           sample configs; every example must validate
lab/                network-namespace lab, smoke test, phase gates
deploy/appliance/   VMware OVA: build scripts, rootfs overlay (systemd units,
                    first-boot setup), OVF template, QEMU boot test
docs/               architecture, effort log
```

The appliance build (`deploy/appliance/build.sh`) needs Docker with
linux/amd64; `boot-test.sh` boots the result in QEMU with VMware device
models (pvscsi, vmxnet3) and checks first boot. Run both after any change
under deploy/appliance or to what ngfwd needs at runtime.

## Known phase 1 limits

IPv4 only. Static routes only, applied at commit and re-applied every 10 s
by ngfwd (they can't go in before interfaces are up). A default route in the
default VRF overrides the deployment's (networkd re-applies outside when it is
removed); the mgmt default route stays with the deployment settings. Likewise an
address on inside/outside in the config overrides the deployment's
(internal/nicaddr writes a networkd file that wins over first boot's); mgmt's
address is never touched. DHCP servers run in Kea (shipped in bundles like FRR); one subnet per served
interface, so the same network can't be served twice (Kea forbids duplicate
subnets, even in different VRFs). App Identification policy (step 2): with rules that name applications, connections go
through the rule base until appidd settles the app (ct mark bits: done 12,
final 13, denied 14, start-logged 15); internal/appid embeds the catalog,
which build.sh checks against the nDPI build. Rules may also name categories
(category:<name>) and application_groups (apps + categories, no nesting);
the compiler expands both to app IDs. IPS: allow rules with an ips_profile
are tagged in the ct mark; chain ips (forward, filter + 10) queues their
packets to Suricata (NFQUEUE 2-3, bypass), which only marks packets with the
signature severity (packet mark bits 24-27); chain ips_enforce (filter + 20)
drops what the rule's profile blocks and sets the denied bit; ngfwd turns
Suricata's EVE alerts into "ngfw-threat" journal lines (rule and action from
the connection's ct mark via conntrack -G). Traffic to the firewall itself is fixed policy, not configurable:
zoned interfaces may ping it and nothing else; unzoned interfaces (mgmt) are
unfiltered. NAT is masquerade only. A commit (or rollback) that changes the compiled
policy flushes conntrack, so established sessions are re-evaluated against
it; tag registration flushes the host's entries, daemon start flushes all.
lab/gate-sessions.sh checks this. Rules naming applications allow at most
compiler.AppPendingPackets (40) packets of a connection before its app is
known, tagged with the rule so its IPS profile inspects them. Inspection
state (internal/nfqueue: is the queue bound?) is reported in show ips/app. Config is edited as YAML
(`fwctl load`), not with `set`-style commands yet. The appliance's tag API
certificate is self-signed. Upgrades (signed bundles, `fwctl upgrade`) cover
SJB-OS files only, not the kernel or Debian packages; 0.2.0 and earlier
must be redeployed once to get the updater. One web UI user, no roles.
IPv4 only, and IPv6 is out of scope until Steve says otherwise. In real
use on ESXi; boot-test.sh in QEMU is the pre-release check.

## Conventions

- Go for control-plane services; C only for appidd (nDPI, libnetfilter_queue).
- Standard library first. Current third-party deps: gopkg.in/yaml.v3 only. Ask
  before adding another.
- Config is YAML on disk, Go structs in memory. The schema lives in
  internal/config/types.go; any field added there needs validation and a test.
- Validation returns all errors at once (errors.Join), each prefixed with its
  path, e.g. `rules[2] "block-p2p": unknown zone "dmz"`.
- Table-driven tests. Compiler output is pinned by golden files in
  internal/compiler/testdata: after an intended change run
  `go test ./internal/compiler -update` and review the diff. CI checks every
  golden file parses with `nft -c`.
- Each phase has a gate script in lab/ that must pass in CI.
- Never filter the management interface; every commit path must support an
  auto-rollback timer (commit confirmed). A pending confirmation is kept in
  `<state>/pending.json` so it survives restarts; anything that restarts
  ngfwd on purpose (upgrades) refuses while one is pending.

## Commands

```bash
nix develop                 # toolchain
make test                   # go vet + go test ./...
make validate               # fwctl validate examples/*.yaml
./bin/fwctl compile examples/lab.yaml   # print the ruleset, offline
VERSION=x.y.z deploy/appliance/build.sh                     # build the OVA and .upgrade
BUNDLE_ONLY=1 VERSION=x.y.z deploy/appliance/build.sh       # just the .upgrade (fast)
deploy/appliance/boot-test.sh build/appliance/sjb-os-LAST.raw build/appliance/sjb-os-x.y.z.upgrade
deploy/appliance/boot-test.sh build/appliance/sjb-os-x.y.z.raw   # boot-test it (in nix develop)
```

### Web UI development

The UI's static files are embedded in ngfwd, so rebuild ngfwd after editing
them. To try the UI on a Mac, run ngfwd with stub `-nft` and `-conntrack`
scripts that exit 0, a relative `-socket` (macOS limits socket paths to 104
characters), `-bootstrap examples/basic.yaml`, a `-web-users` file made with
`fwctl web-passwd -web-only -file`, and `-ui-listen 127.0.0.1:9443 -ui-dev-http`. That
flag serves plain HTTP and is refused on anything but loopback; browsers
accept the UI's Secure cookie on `localhost`. Never use it on the appliance.

### Test harness (development and CI only)

The phase gates run ngfwd against a network-namespace lab (users, fw,
internet). It needs Linux with root, so on a Mac build Linux binaries and run
it in a privileged container (this is how it was verified):

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/ ./cmd/...
docker run --rm --privileged -v "$PWD":/src:ro -w /src debian:stable-slim bash -c \
  'apt-get update -qq && apt-get install -y -qq iproute2 iputils-ping nftables conntrack python3 curl make procps && make lab-gate1'
```

On Linux: `make build && sudo make lab-gate1`. The gate script shows how to
drive ngfwd directly (`-state`, `-socket`, `-api-listen`, `-api-keys`) for
tests; never document that as a way to deploy.

## Effort log

This project exists to produce evidence. After a meaningful session, append a
row to docs/effort-log.md: date, phase, what got done, human hours (ask Steve
if unknown, never guess), and notes.

## Commits

Commits are SSH-signed via the global git config; don't override signing.
Small commits, imperative subject lines.
