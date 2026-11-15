# SJB-OS appliance guide

**An experimental demonstration of AI-generated software for isolated lab
use. Not a commercial, supported, or production-ready security product. Do
not rely on it to protect production systems. Working code does not
establish security effectiveness, resilience, or operational readiness.**
Its project-specific code was generated with Claude Code under Steve Boyle's
direction and reviewed with ChatGPT's help; it relies on Linux netfilter,
nDPI, Suricata, FRRouting, Kea and Debian for the real work (see the repo's
README).

SJB-OS (Stops Junk at the Border) is the hobby-ngfw
firewall packaged as a VMware OVA, and that is the only supported way to run
it. The VM is Debian 13 with ngfwd, nftables and open-vm-tools: 3 vmxnet3
NICs, 2 vCPU, 2 GB RAM, 8 GB disk. Give it 4 GB of RAM to use the IPS.

## Before you start

- The OVA from [Releases](https://github.com/stevejboyle/hobby-ngfw/releases),
  checked against its `.sha256` file.
- vSphere 8.0 Update 1 or later (ESXi host, standalone or under vCenter). The
  OVA uses virtual hardware version 20 and the Debian 12 64-bit guest type.
- Three port groups (new or existing):

  | Network | Adapter | Purpose |
  | --- | --- | --- |
  | mgmt | Network adapter 1 | Web UI, SSH and the tag API. Never filtered by policy. |
  | inside | Network adapter 2 | Protected zone. Clients use the firewall as their gateway. |
  | outside | Network adapter 3 | Upstream / internet. Inside traffic is NATed to this address. |

- Inside should be an isolated port group: the firewall must be the only way
  out of it.
- To use VLAN subinterfaces (see [VRFs and VLANs](#vrfs-and-vlans)), set the
  inside and/or outside port group's VLAN ID to 4095 (VLAN trunking, "virtual
  guest tagging"), so tagged frames reach the VM.
- Inside clients need an address in the inside subnet, the firewall's inside
  IP as gateway (10.10.1.1 by default), and a DNS server: set them statically,
  or have the firewall hand them out (see [DHCP server](#dhcp-server)). The
  appliance doesn't run DNS.

## Deploy

1. **Deploy OVF Template** in vCenter or the ESXi Host Client and select the
   `.ova` file.
2. **Map the networks** as in the table above. Keep the adapter order: first
   boot names the NICs mgmt, inside, outside by it.
3. **Settings.** vCenter shows them in the deployment wizard. Standalone ESXi
   does not pass wizard settings to the VM; instead, before first power-on,
   add them under *Edit Settings → VM Options → Advanced → Configuration
   Parameters* as `guestinfo.ngfw.<key>`, e.g. `guestinfo.ngfw.mgmt_ip` =
   `192.168.10.20/24`. Anything you leave out takes the default.

   | Key | Default | Notes |
   | --- | --- | --- |
   | hostname | sjb-fw | |
   | admin_password | generated | `admin`'s one password (SSH, console, web UI), 10+ characters; shown on the VM console until you change it. A shorter one is replaced by a generated one |
   | admin_ssh_key | none | Public key for user `admin` |
   | root_ssh_key | none | Public key that may log in as root over SSH, for recovery. None: root has no SSH access. No key ships with SJB-OS |
   | root_password | none | Root's VMware console password, 10+ characters (never accepted over SSH). None: root's console login is locked |
   | mgmt_ip | DHCP | CIDR, e.g. 192.168.10.20/24 |
   | mgmt_gateway, mgmt_dns | none / from DHCP | Used for management traffic only |
   | inside_ip | 10.10.1.1/24 | The inside clients' gateway |
   | outside_ip | DHCP | CIDR |
   | outside_gateway, outside_dns | none / from DHCP | Default route for forwarded traffic |

   Settings apply once, at first boot. To change them later, redeploy.
4. **Power on** and open the console. Within a minute or two it shows a
   the SJB-OS mark, each NIC's MAC and address, the ruleset revision, the web UI
   address and "SJB-OS ready: standing guard at the border." Check the MACs against the
   adapters in vSphere.
5. **Open the web UI** at `https://<mgmt-ip>/` and log in as `admin` with the
   password from the console. The certificate is self-signed, so the browser
   warns once.

## What first boot sets up

- NICs renamed `mgmt`, `inside`, `outside` and pinned to their MACs.
- Management in its own routing table (VRF `vrf-mgmt`), so a mgmt gateway
  never carries forwarded traffic. The web UI, SSH and the tag API answer
  only on mgmt.
- User `admin`, whose login (SSH and console) is the SJB-OS CLI, not a
  Unix shell, and who has no sudo. SSH host keys, a self-signed TLS
  certificate (web UI and tag API), a tag API key, and one password for
  `admin` that works for SSH, the console and the web UI.
- Root: only what you set at deploy time, `root_ssh_key` and/or
  `root_password` (see [Root access](#root-access)). Nothing else can log
  in as root.
- A starter policy committed as revision 1 (`/etc/ngfw/initial.yaml`):
  - inside may reach outside, NATed to the outside address
  - hosts tagged `quarantine` are blocked
  - everything else between zones is denied
- Inside and outside can ping the firewall but reach no service on it.
- The firewall rules load before any interface comes up, on every boot.

## Web UI

`https://<mgmt-ip>/`, user `admin`. Everything `fwctl` does, with forms:

- **Dashboard:** running revision, rule and object counts, quarantined hosts,
  interfaces and addresses, and **Activity** charts for the last hour, day
  or week (the choice is remembered; they refresh every 30 seconds):
  - **Throughput:** traffic received on each data interface over time
    (outside's is your downloads, inside's your uploads); hover for in and
    out at any point.
  - **Top applications:** bytes and connections per application.
  - **Threats:** IPS matches over time by severity, blocked and alerted
    totals, and the top signatures (click one for its Threat log entries).
  - **Top hosts:** the busiest addresses by bytes, with connections and
    threats from each (click one for its Traffic log entries).

  ngfwd takes a sample every minute and keeps a week, so the charts fill in
  over the first minutes after an upgrade. Applications and hosts count all
  forwarded traffic (App Identification on), when connections end; threats count what
  the IPS logs. `show statistics [1h|24h|7d]` in the CLI shows the same.
The menu groups the pages: **Security** (Policy, NAT, Objects, Applications,
IPS, Tags), **Networking** (Interfaces, Routing, DHCP) and **System** (Logs,
Revisions, Administration).

- **Policy, NAT, Objects, Interfaces:** add, edit, delete and reorder security
  rules, NAT rules, addresses, address groups (static or tag-based),
  services, zones, interfaces and static routes. Edits go to the candidate config and are
  validated as you save; a bar at the top shows there are uncommitted
  changes, with the diff, Discard and Commit.
- **Commit:** the auto-rollback timer is on by default (5 minutes). A bar
  counts down until you press Confirm; if you don't, the previous revision
  comes back on its own. The timer survives an ngfwd restart or a reboot:
  if the deadline passed meanwhile, the rollback happens as ngfwd starts.
  Upgrades wait until nothing is pending.
- **Tags:** register and unregister hosts, with expiry. Applies at once, no
  commit.
- **Revisions:** every commit with author (`web:admin` for UI commits), view
  the config of any revision, roll back.
- **Logs:** the data-plane (traffic) and management (system) logs; see
  [Logs](#logs).
- **Administration:** upgrades (below) and the password.

`admin` has one password for the web UI, SSH and the console. Change it on
System → Administration or with `passwd` in the CLI; either changes all three. After
five wrong passwords from one address, logins from it are refused for a while
(15 seconds, doubling up to 15 minutes). Sessions end after 8 hours idle and
when ngfwd restarts.

Saving from the UI rewrites the candidate YAML, so comments in it are not
kept.

## Sayings

SJB-OS stops junk at the border, and says so now and then:

- **Console and login screen:** the SJB-OS mark with the addresses, and the
  generated password until you change it.
- **SSH:** a pre-login banner ("authorised users only, everyone else is
  turned back at the border") and a message of the day with live status
  (running revision, rule count, quarantined hosts) and a saying from
  `/usr/share/sjb-os/sayings.txt`.
- **`sjb` in the CLI:** a word from the border guard, and the firewall's
  status.
- **Web UI:** each page opens with a one-line tagline; commits end with
  "New rules, same vigilance."
- **API:** every response carries `X-SJB-OS: Stops Junk at the Border`.
- **vSphere:** VMware Tools reports the guest as "SJB-OS (Stops Junk at the
  Border; Debian 13 underneath)".

Machine-readable output (JSON, the tag API's XML responses, exit codes, log
prefixes) is unchanged, so integrations and scripts never see a joke.

## The CLI

SJB-OS gives operators a CLI rather than a Unix shell. SSH to
the mgmt address as `admin` (or log in on the VMware console) and you get the
`admin@<hostname>>` prompt. There is no bash, no sudo, no file transfer and
no port forwarding. `help` lists the commands:

| Command | What it does |
| --- | --- |
| `show status`, `show version` | Running revision, pending confirm; SJB-OS version and upgrade history |
| `show running`, `show candidate`, `show diff` | The config as YAML, and what changed |
| `show ruleset`, `show revisions`, `show revision N` | Compiled nftables ruleset; commit history; an old config |
| `show tags [TAG]`, `show interfaces`, `show api-keys` | Registrations, addresses, tag API keys |
| `show arp [INTERFACE]` | ARP table: which neighbours answered, with their MACs |
| `show routes [vrf NAME]` | Static routes from the config (installed or not, and why), then the routing tables: default, each VRF, mgmt |
| `show vrf` | VRFs with their table, interfaces and state |
| `show bgp`, `show ospf` | BGP neighbors (state, uptime, prefixes) and OSPF neighbors, every VRF |
| `show rib [vrf NAME]` | The routing table as FRR sees it, with the protocol of each route |
| `show app`, `show app catalog [TEXT]`, `show app categories` | Applications App Identification has seen (connections, bytes); every application it can identify; its categories |
| `show dhcp`, `show dhcp leases [INTERFACE]` | DHCP servers (range, gateway, DNS, active leases); the leases handed out |
| `load` | Paste a whole config (YAML), end with a line `end` |
| `revert` | Discard uncommitted changes |
| `commit [-m "MSG"] [-confirm 5m]`, `confirm`, `rollback N` | Apply, accept, go back |
| `tags register IP TAG... [-ttl 1h]`, `tags unregister IP TAG...` | Tag hosts |
| `ping HOST [COUNT]`, `passwd`, `sjb`, `exit` | |
| `configure` | Configuration mode (below) |

**Tab** completes commands, object names and values; **?** lists what can
come next, with a line of help each. Up/down arrows recall earlier commands;
Ctrl-A/E, Ctrl-U/K/W and Ctrl-L work as in bash.

### Configuration mode

`configure` switches the prompt to `admin@<host>#` and gives you
`set`-style editing of the candidate config:

```
admin@sjb-fw> configure
[edit]
admin@sjb-fw# set address web-srv cidr 10.10.1.80
admin@sjb-fw# set service ssh protocol tcp ports 22
admin@sjb-fw# set rule allow-ssh from inside to outside source [ inside-net web-srv ] service ssh action allow
admin@sjb-fw# move rule allow-ssh top
admin@sjb-fw# show rule allow-ssh
admin@sjb-fw# show diff
admin@sjb-fw# commit -m "ssh out" -confirm 5m
admin@sjb-fw# exit
admin@sjb-fw> confirm
```

| Command | What it does |
| --- | --- |
| `set OBJECT NAME [ATTR VALUE]...` | Create an object or set attributes; several attributes on one line |
| `delete OBJECT NAME` | Delete it |
| `delete OBJECT NAME ATTR` | Clear an attribute (lists go back to any) |
| `delete OBJECT NAME ATTR VALUE` | Remove a list member; `[ a b ]` for several |
| `move rule\|nat NAME top\|bottom\|before X\|after X` | Reorder |
| `rename OBJECT OLD NEW` | Rename; every reference follows |
| `show [OBJECT [NAME]]` | The working config as YAML (`show diff`, `show status` and the other operational shows work too) |
| `commit`, `revert`, `run COMMAND`, `exit` | Commit; throw away changes; run an operational command; leave |

Objects are `system`, `zone`, `interface`, `address`, `address-group`,
`service`, `rule`, `nat` and `route`. For list attributes (`from`, `to`,
`source`, `destination`, `service`, `application`, `static`), `set` adds
members and `any` replaces the whole list.

Edits are saved to the candidate as soon as the config is valid. While it
isn't (a new rule with no action yet), the change stays in your session and
the CLI says why once; `commit` refuses, and `exit` warns before throwing it
away. Edits from the web UI and the CLI go to the same candidate, so if two
people edit at once, the last save wins.

One command at a time works over SSH too, which is handy for scripts and for
editing the config on your own machine:

```bash
ssh admin@<mgmt-ip> show running > fw.yaml
vi fw.yaml
ssh admin@<mgmt-ip> load < fw.yaml
ssh admin@<mgmt-ip> show diff
ssh admin@<mgmt-ip> 'commit -m "allow DNS only" -confirm 5m'
ssh admin@<mgmt-ip> confirm          # within 5 minutes, or it rolls back
```

The config format is the one `show running` prints; see
`examples/basic.yaml` in the repo for every object type.

### What a commit does

A commit validates the candidate, compiles it and checks the result with
`nft -c` and (when used) FRR and Kea, so a config they reject changes
nothing. Then, in this order:

1. The new revision, and for `-confirm` its rollback target and deadline,
   are written to disk. If that fails, nothing changes.
2. The firewall policy is applied in **one atomic nftables transaction**:
   either the whole new ruleset is in force or the old one still is.
3. The revision becomes the running one. If that can't be recorded, the
   previous ruleset is put back and the commit fails. If even that fails,
   `show status` (and a bar in the web UI) reports a **recovery** state:
   enforcement may not match the running revision until the next good
   commit or a restart of ngfwd.
4. If the policy changed, **every existing connection is re-evaluated**:
   ngfwd clears the connection-tracking table, so on its next packet each
   connection meets the new rules as if new. Connections the new policy
   allows carry on (TCP is picked up mid-stream; NATed and long-idle
   connections may need to reconnect); connections it denies stop. A
   connection that a rule allows only by application is identified again
   from mid-stream and may be cut off, so expect to reconnect those.
   Management (mgmt) is never filtered and isn't affected. A commit whose
   compiled firewall ruleset is unchanged leaves connections alone.

Only step 2 is atomic. Routing (FRR), DHCP (Kea), the IPS, interface
addresses and VLANs **converge afterwards**: the commit reports problems
there as warnings, and ngfwd keeps retrying (routes and interfaces every
10 seconds); they are not rolled back with the policy. A rollback (manual,
or automatic when a `-confirm` commit isn't confirmed) is a new commit of
the old revision and goes through the same steps; if an automatic rollback
fails, the unconfirmed revision stays in force, `show status` says so, and
ngfwd retries every minute (and at its next start).

**Tag hosts** from anything that can reach mgmt, with the key from
`show api-keys`:

```bash
curl -k -H "X-API-Key: $KEY" -d '{"ip":"10.10.1.50","tags":["quarantine"],"ttl":3600}' \
  https://<mgmt-ip>:8443/api/v1/tags/register
curl -k -H "X-API-Key: $KEY" -d '{"ip":"10.10.1.50","tags":["quarantine"]}' \
  https://<mgmt-ip>:8443/api/v1/tags/unregister
curl -k -H "X-API-Key: $KEY" https://<mgmt-ip>:8443/api/v1/tags
```

A tag takes effect immediately, with no commit, and cuts the host's existing
sessions. NAC, SOAR and EDR integrations that send XML user-ID messages can
point at `https://<mgmt-ip>:8443/api/`: `type=user-id` with a `uid-message`
register/unregister is supported, with the key as `key=` (or an `X-API-Key`
header).

## Interface addresses

First boot gives `inside` and `outside` their addresses from the deployment
settings (`inside_ip`; `outside_ip`, or DHCP when it's blank). To change one
later, set the interface's address in the config and commit. In configure
mode:

```
set interface outside address 192.168.1.20/24
commit
```

Or in YAML (`interfaces: - name: outside ... address: 192.168.1.20/24`), or
on the web UI's Networking → Interfaces page. The configured address replaces the deployment's
address or DHCP on that interface (its DNS servers from the deployment are
kept). Remove it and commit, and the deployment settings come back. Pair it
with a [default route](#static-routes) when outside moves off DHCP.
`show interfaces` lists each configured address and whether it's applied; the
Interfaces page shows the same, with the ARP table.

Before taking a configured address, the firewall checks that no other device
on the network is using it, then announces it (gratuitous ARP), so a router
that still remembers the address on another device switches to the firewall
straight away. If another device does have the address, it isn't applied:
`show interfaces` says so, and you should pick a free one. The firewall also
announces its addresses whenever an interface comes up.

`mgmt`'s address always comes from the deployment settings, so a commit can't
cut off management access; an address on it in the config is informational.

## VRFs and VLANs

A VRF is a separate routing table: interfaces in it only route among
themselves (and to what its routes point at). `default` (the main table) and
`mgmt` (the management VRF from first boot) are built in; add your own on
the web UI's Networking → Interfaces page, in YAML, or in configure mode.

VLAN subinterfaces give VRFs (and zones) something to hold. Name an
interface `parent.vlan`, such as `inside.20`, and ngfwd creates VLAN 20 on
inside, puts it in its VRF and gives it its address:

```yaml
vrfs:
  - name: lab-a          # table picked automatically from 1001 (or set table:)
  - name: lab-b
interfaces:
  - name: inside.20
    zone: labs
    vrf: lab-a
    address: 172.16.0.1/24
  - name: inside.30
    zone: labs
    vrf: lab-b
    address: 172.16.0.1/24   # the same subnet again: fine, it's another VRF
routes:
  - name: lab-a-out          # a VRF's own default route
    vrf: lab-a
    destination: 0.0.0.0/0
    gateway: 192.0.2.1
    interface: outside       # out through the default VRF's outside
  - name: lab-a-to-b         # route leaking: hand 172.17/16 to VRF lab-b
    vrf: lab-a
    destination: 172.17.0.0/16
    next_vrf: lab-b
```

In configure mode the same is `set vrf lab-a`, `set interface inside.20
zone labs vrf lab-a address 172.16.0.1/24`, `set route lab-a-to-b vrf lab-a
destination 172.17.0.0/16 next-vrf lab-b`.

- VLANs go on inside or outside (not mgmt), IDs 1-4094; the port group must
  trunk VLANs (VLAN ID 4095 in vSphere).
- Only VLAN subinterfaces join VRFs in this release; the inside and outside
  NICs stay in the default VRF, where first boot configured them.
- Each VRF gets its own conntrack zone, so the same addresses in two VRFs
  are separate connections. Zones and rules work across VRFs as usual:
  a rule from zone labs to zone outside covers both lab VRFs.
- Like routes, ngfwd creates the devices at commit, puts them back if they
  disappear, and removes them when you delete them from the config. It
  never touches mgmt, inside, outside or vrf-mgmt.
- `show vrf` and `show routes vrf NAME` in the CLI, and the Interfaces page,
  show what's in place.

## BGP and OSPF

SJB-OS runs BGP and OSPF with FRRouting, configured like everything else
(web UI **Routing** tab, configure mode, or YAML) and applied at commit, with
diff, commit-confirmed and rollback. FRR itself is installed by the upgrade:
the bundle carries it, and it installs in the background a minute or so after
the upgrade. Until then, routing settings commit with a warning and start
once FRR is in.

```yaml
routing:                        # one entry per VRF that runs a protocol
  - name: default               # the VRF
    router_id: 10.10.1.1
    bgp_asn: 65010              # turns BGP on
    bgp_networks: [10.10.0.0/16]
    bgp_redistribute: [ospf]    # connected, static, ospf
    ospf: true
    ospf_redistribute: [static, bgp]
bgp_neighbors:
  - name: upstream
    address: 192.0.2.1
    remote_as: 64500
    import: from-upstream       # prefix lists; none means everything
    export: to-upstream
  - name: core
    address: 10.10.1.2
    remote_as: 65010            # our own AS: iBGP
    next_hop_self: true
ospf_interfaces:
  - name: inside                # the interface
    area: 0
    cost: 10
  - name: outside
    area: 0
    passive: true               # announce the subnet, no adjacency
prefix_lists:
  - name: to-upstream
    entries: ["permit 10.10.0.0/16 le 24", "deny any"]
```

In configure mode: `set routing default router-id 10.10.1.1 bgp-asn 65010
ospf yes`, `set bgp-neighbor upstream address 192.0.2.1 remote-as 64500
import from-upstream`, `set ospf-interface inside area 0 cost 10`,
`set prefix-list to-upstream entry "permit 10.10.0.0/16 le 24"`.

- A BGP instance runs in any VRF with a routing entry; neighbors name their
  VRF. OSPF runs in the VRF of the interfaces you list.
- The firewall accepts BGP (TCP 179) only from configured neighbor addresses
  and OSPF only on OSPF interfaces; nothing else changes about what can
  reach it.
- Learned routes go into the kernel (`show routes` marks them `proto bgp` /
  `proto ospf`); policy still decides what traffic may use them.
- `static` in a redistribute list means SJB-OS's static routes.
- Not yet: BGP passwords, route-maps beyond prefix lists, BFD, IPv6.
- Rolling back to a version without BGP/OSPF won't start with a config that
  uses them: delete the routing settings and commit first.

## DHCP server

SJB-OS can hand out addresses on any data interface (inside, outside, VLAN
subinterfaces, in any VRF), with ISC's Kea DHCP server. Configure it in the
web UI **DHCP** tab, in configure mode, or in YAML; it applies at commit like
everything else. Kea is installed by the upgrade: the bundle carries it, and
it installs in the background a minute or so after the upgrade. Until then,
DHCP servers commit with a warning and start once Kea is in.

```yaml
interfaces:
  - name: inside
    zone: inside
    address: 192.168.150.1/24      # required: the served network
dhcp_servers:
  - name: inside                   # the interface
    range: 192.168.150.100-192.168.150.199
    gateway: 192.168.150.1         # optional; default: the interface's address
    dns: [9.9.9.9]                 # optional; default: the firewall's own DNS servers
    domain: home.example           # optional
    ntp: [192.168.150.1]           # optional
    lease_time: 86400              # seconds; default a day
    options:                       # any other option, CODE=VALUE
      - 66=tftp.home.example       # TFTP server (phones, PXE)
      - 150=0x0a0a0a0a             # 0x...: raw bytes, for options Kea doesn't know
dhcp_reservations:
  - name: printer
    interface: inside
    mac: 52:54:00:12:34:56
    address: 192.168.150.20        # in or out of the range
```

In configure mode: `set interface inside address 192.168.150.1/24`,
`set dhcp-server inside range 192.168.150.100-192.168.150.199 domain
home.example`, `set dhcp-server inside option "66=tftp.home.example"`,
`set dhcp-reservation printer interface inside mac 52:54:00:12:34:56 address
192.168.150.20`, then `commit`. Check with `show dhcp` and `show dhcp leases`.

- The interface needs its address in the config: that is the network served,
  and clients get it as their gateway unless you set `gateway`.
- Without `dns`, clients get the DNS servers the firewall itself uses (the
  deployment's, or what DHCP on outside learned). SJB-OS doesn't run a DNS
  service, so it never hands out its own address as DNS.
- The firewall accepts DHCP (UDP 67) on each served interface; nothing else
  changes about what can reach it.
- A commit with a config Kea rejects (an option code Kea doesn't know, given
  as text) fails before anything is applied. Use `0x...` for such options.
- Leases survive restarts and upgrades (Kea keeps them in
  `/var/lib/kea/kea-leases4.csv`); Kea's own messages, including each lease
  handed out, are in `show log system` under source `dhcp`.
- With no DHCP servers in the config, Kea is stopped.
- Not yet: DHCP relay, failover, IPv6 (DHCPv6), serving the same network on
  two interfaces (overlapping addresses in different VRFs), dynamic DNS.
- Rolling back to a version without DHCP won't start with a config that uses
  it: delete the DHCP servers and reservations and commit first.

## Static routes

Routes go in the config's `routes` section: on the web UI's Networking → Interfaces page,
in configure mode (`set route ...`), or in YAML. They cover networks behind
a router on the inside, management-only networks, and the default route:

```yaml
routes:
  - name: lab-net
    destination: 10.20.0.0/16
    gateway: 10.10.1.254       # a next hop on a directly connected network
  - name: monitoring
    destination: 192.0.2.0/24
    gateway: 192.168.10.1
    table: mgmt                # the management VRF, for the firewall's own traffic
  - name: internet
    destination: 0.0.0.0/0     # overrides the deployment's outside_gateway
    gateway: 203.0.113.1
    interface: outside
```

**Default routes.** At deployment the forwarding default route comes from
`outside_gateway` (or DHCP), and the management one from `mgmt_gateway`. A
`0.0.0.0/0` route in the default VRF takes over from the deployment's: it
wins over a DHCP default and replaces a static one. Delete it and commit, and
the deployment's default comes back. The management default route can't be
set in the config, so a bad commit can't cut off management access; VRFs you
create have no deployment default and can have their own.

Routes are part of the commit: they show in the diff, are installed when you
commit, roll back with commit-confirmed, and are removed when you delete
them. ngfwd owns only the routes it installed, and puts them back within
about 10 seconds if anything removes them (for example an interface going
down and up). A route that can't be installed yet, usually because its
gateway isn't on a connected network, doesn't fail the commit: you get a
warning, `show routes` says why, and ngfwd keeps trying.

A route only lets traffic reach a network. The firewall still decides what
may pass: the network behind an inside router is part of the inside zone,
but rules that name `inside-net` as their source don't cover it until you
add an address for it and include it.

## Root access

Root is for recovery, not operations, and only you decide who has it: no
root key or password ships with SJB-OS, and the vendor has no way in.

- **SSH:** key only, with the key you set as `root_ssh_key` at deploy time
  (`ssh root@<mgmt-ip>`). It lives in `/etc/ngfw/root_authorized_keys`,
  which upgrades never touch; edit it there as root to add or change keys.
  Passwords are always refused for root over SSH.
- **VMware console:** root can log in with the `root_password` you set at
  deploy time (change it later with `passwd` as root).
- **Neither set:** root can't log in. To recover, open the VMware console,
  interrupt the boot at the GRUB menu (hold Shift or press Esc), add
  `init=/bin/bash` to the `linux` line and boot: you get a root shell to
  fix things (for example, add a key to `/etc/ngfw/root_authorized_keys`).
  Anyone with that much access to vSphere could do the same.
- **Appliances from before 0.9.9** carried a development key. Upgrading
  moves that appliance's key to `/etc/ngfw/root_authorized_keys`, so its
  owner keeps access; new deployments never get it.

Root-only tasks for now: editing tag API keys (`/etc/ngfw/api-keys`, one
`<name> <scopes> <key>` per line, scopes `tags:read`/`tags:write`, keys of
24+ characters, then `systemctl restart ngfwd`), resetting a forgotten
`admin` password (`fwctl web-passwd`, which sets SSH, console and web UI
together), and Debian updates (`apt update && apt upgrade`). The full
journal (`journalctl`) is there too, beyond what the Logs views show.

## Applications (App Identification)

SJB-OS identifies the application in each connection: YouTube, Netflix,
Teams, BitTorrent, SSH, DNS and about 490 more (`show app catalog`, or the
web UI's Security → **Applications** page). It looks at the first packets of each TCP/UDP
connection with nDPI, the open-source deep packet inspection library, which
recognises apps by protocol behaviour, TLS server names, HTTP hosts and
fingerprints, then lets the rest of the connection pass at kernel speed.

### Application policy

Rules can name applications: allow only some, or block some, by what the
traffic is rather than its port.

- **Web UI:** on the Policy page, a rule's **Applications** picker searches
  the catalog by name or category (e.g. "video", "vpn"); click to add or
  remove. None chosen means any application.
- **CLI:** `set rule no-streaming application [ youtube netflix twitch ]`;
  Tab and `?` list the names. **YAML:** `application: [youtube, netflix]`
  (any case).
- `unknown` matches connections App Identification couldn't identify.
- **Categories:** `category:video`, `category:socialnetwork`, `category:vpn`
  and the other nDPI categories match every application in them
  (`show app categories` lists them with their sizes).
- **Application groups** name a set of applications and categories, for
  rules to use: on the web UI's **Objects** page, or
  `set application-group streaming member [ youtube netflix category:video ]`,
  or YAML:

  ```yaml
  application_groups:
    - name: streaming
      members: [youtube, netflix, category:video]
  ```

  The picker on the Policy page offers applications, categories and groups;
  its **Show** menu narrows it to one kind. Groups can't contain groups.

```yaml
rules:
  - name: no-streaming          # first: the first matching rule wins
    from: [inside]
    to: [outside]
    application: [youtube, netflix, twitch]
    action: deny
    log: true
  - name: inside-out
    from: [inside]
    to: [outside]
    action: allow
```

How it behaves: App Identification needs a connection's first packets to
name it (for TLS, the client hello with the server name). Until then, an
allowed connection's packets pass and the rules look at it again; once the
application is known:

- a **deny/reset** rule for it drops (or resets) the connection then, and
  every later packet of it; with logging on it logs once;
- an **allow** rule for it lets it continue, and from then on it takes the
  fast path;
- a rule that allows *only* certain applications cuts off anything else as
  soon as it's identified (it falls through to the rules below, often the
  default deny).

Put application rules above broader rules: a rule below one that matches
everything it would never matches, and a commit warns about it ("never
matches: rule ... above it matches everything it would").

Policies without application rules behave exactly as before. With App Identification
off (`set system app-identification off`), rules that name applications are skipped
with a warning.

- **Applications page / `show app`:** every application seen since App Identification started,
  with connections and bytes, counted when connections end.
- **Traffic log:** rules with logging on now also write an **end** entry
  when an allowed connection closes, with its application, category, bytes,
  packets and duration (`type`, `app`, `category`, `bytes`, `packets`,
  `duration` columns). Start entries still come first, before the app is
  known, and are the only entries for denied connections.
- On by default. `set system app-identification off` (and commit) stops classification;
  `delete system app-identification` turns it back on.
- **Before identification**, a rule that names applications lets a
  connection through for at most **40 packets** (both directions together)
  while its application isn't known. App Identification settles every
  connection within its first 32 packets, so normally the rule's
  application match decides well before the limit. Those packets carry the
  rule's IPS profile: the IPS inspects them, so a signature in the first
  request is caught. Past the limit, an unidentified connection is treated
  like any other unidentified traffic: the rules below decide (often the
  default deny).
- **If App Identification isn't working** (`appidd` stopped, starting, or
  overloaded), traffic isn't classified: the ruleset hands packets to it
  with bypass, so they go straight on. Rules that don't name applications
  are unaffected. A rule that does still allows an unidentified connection
  only for its first 40 packets, so an application-restricted allow never
  becomes an unrestricted one; short connections (a small web request) can
  complete within that window. `show app` and the Applications page say
  **classifying**, **unavailable** or **off**.
- It ships in the upgrade bundle: `appidd` plus nDPI 6.0 (built for
  SJB-OS; Debian's is from 2021) and libnetfilter-queue, installed in the
  background a minute or so after the upgrade.
- Not yet: nDPI's risk scores in rules, zones on end entries, IPv6.

## Intrusion prevention (IPS)

SJB-OS inspects the traffic of chosen allow rules with Suricata and the
free Emerging Threats Open signatures (about 53,000: exploits, malware and
command-and-control traffic, scans, policy violations), and blocks or logs
what matches.

**Give the VM 4 GB of RAM** before using it: Suricata with the full set uses
about 1 GB. A commit warns on less. Suricata also needs a CPU with SSE4.2
(every x86-64 CPU since about 2008; only an old EVC baseline would hide it):
without it the package doesn't install, and `show ips` keeps reporting
Suricata as not installed.

- **Turn it on for a rule:** pick an **IPS profile** on an allow rule
  (Policy page), or `set rule inside-out ips-profile default`, or YAML
  `ips_profile: default`. Only that rule's traffic is inspected; traffic no
  rule allows never reaches the IPS.
- **Profiles** say what each signature severity gets: **block** (drop the
  packet and the rest of the connection, and log it), **alert** (let it
  through, log it) or **ignore**. The built-in **default** blocks critical
  and major, alerts on minor and ignores informational. Make your own on
  the **Objects** page, or:

  ```
  set ips-profile strict critical block major block minor block informational alert
  set rule web-in ips-profile strict
  ```

  ```yaml
  ips_profiles:
    - name: strict
      critical: block
      major: block
      minor: block
      informational: alert    # unset severities take the default's action
  rules:
    - name: web-in
      action: allow
      ips_profile: strict
  ```

- **Threat log:** every match a profile blocks or alerts on, in the web
  UI's **Logs → Threats** or `show log threat`: rule, profile, action,
  severity, signature and its ID, application, addresses and ports. Columns
  and queries work as for traffic (`show log threat where severity =
  critical and action = block`).
- **Signatures** download when a rule first uses a profile, then daily, and
  on demand: `request ips update` or **Update signatures now** on the
  **IPS** page. `show ips` (or the IPS page) shows the engine, the signature
  version and counts by severity, the last update and which rules are
  inspected. The firewall needs to reach rules.emergingthreats.net over the
  outside link.
- **False positives:** leave a signature out by its ID (from the threat log):
  `set system ips-disabled-signatures [ 2013504 ]`.
- **Test it** from a client behind the firewall: any traffic containing
  `SJB-IPS-TEST-CRITICAL` (or `-MAJOR`, `-MINOR`, `-INFO`) matches SJB-OS's
  own test signatures at that severity, e.g.
  `curl http://example.com/SJB-IPS-TEST-CRITICAL` is blocked under the
  default profile. [`tools/ips-test.sh`](../../tools/ips-test.sh) tries all
  four. For a fuller workout from a Linux test VM,
  [`tools/fw-traffic-test.sh`](../../tools/fw-traffic-test.sh) makes about 50
  kinds of application traffic for App Identification and 15 harmless IPS triggers
  (the four test strings plus real ET Open signatures at every severity:
  DNS lookups of sinkholed WannaCry kill-switch domains, scanner user
  agents and the like), and prints what the default profile should do with
  each. `-l` lists them without sending anything.
- **Off:** `set system ips off` skips every rule's profile (with a warning)
  and stops the engine; so does removing the last profile from the rules.
- **Inspection state:** `show ips` and the IPS page say what the IPS is
  doing to traffic right now, from the kernel's queue table rather than
  from whether a process runs: **inspecting**, **loading** (inspecting with
  the signatures loaded so far), **starting** or **unavailable** (traffic of
  rules with a profile passes uninspected), or **off**.
- **Fail-open, deliberately:** when the engine isn't receiving traffic
  (starting, stopped, not installed), packets of rules with a profile pass
  uninspected: the ruleset hands them to it with bypass. When its queue is
  full, they also pass uninspected (Suricata's fail-open); the state then
  reports how many. Loading the full set takes a minute or so after boot or
  an update. A lab appliance that must block rather than pass uninspected
  traffic would need fail-closed queues; SJB-OS doesn't offer that.
- It ships in the upgrade bundle: Debian 13's Suricata 7.0.10 (kept patched
  by `apt upgrade`), installed in the background after the upgrade, run as
  `sjb-ips.service`.
- Not yet: exceptions per profile, reset instead of drop, file and URL
  filtering, IPv6.

## Logs

Three logs, under System → **Logs** in the web UI and in the CLI:

- **Data plane (traffic):** one entry per new connection that matches a
  rule with logging on (`log: yes`, the Log box on the Policy page, or
  `set rule NAME log yes`): time, rule, action, zones and interfaces in and
  out, source and destination address and port, protocol, packet length,
  TTL, TCP flags, ICMP type, and the application (App Identification, phase 2: empty
  until then). Rules without logging, and traffic dropped by the final
  default deny, aren't logged.
- **Threats (IPS):** signature matches on rules with an IPS profile (see
  [Intrusion prevention](#intrusion-prevention-ips)).
- **Management (system):** what ngfwd did and who asked (commits with author
  and message, rollbacks, confirmations, web logins and failed logins, tag
  changes, static-route problems, upgrades), plus SSH logins and first boot.

In the web UI, search narrows either log, choose how many of the newest
entries to show, and turn on refresh every 5 seconds to watch it live.
**Columns** chooses what the traffic log shows; the browser remembers the
choice. In the CLI:

```
show log traffic [N] [TEXT] [columns LIST] [where QUERY]
show log traffic columns rule,src,sport,dst,dport,app
show log traffic 200 where zone = inside and dst = 4.2.2.2
show log system [N] [TEXT] [where QUERY]     # e.g. show log system where source = sshd
```

### Searching the logs

A search is plain words (matched anywhere in the entry, as before) or
conditions, `field op value`, joined with `and`, `or`, `not` and
parentheses:

```
zone = inside and dst = 4.2.2.2
app ~ tube or category = media
action != allow and (dport = 22 or dport = 3389)
type = end and bytes > 1000000
src = 10.10.1.0/24 and not proto = udp
```

- Operators: `=` (or `eq`), `!=`, `~` (contains), `!~`, `>`, `<`, `>=`,
  `<=`. Text compares without case; quote values with spaces
  (`app = "Apple iCloud"`).
- Addresses take an IP or a CIDR; numbers also a range (`dport = 1000-2000`).
- Traffic fields: `rule action type from to zone in out interface src dst
  addr sport dport port proto app category bytes packets duration len ttl
  flags icmp`. `zone`, `interface`, `addr` and `port` match either side;
  `!=` on them means neither side.
- System fields: `source level message fields`.
- In the web UI, clicking a value in the traffic table adds it as a
  condition (`and dst = 4.2.2.2`); **Query help** lists every field. In the
  CLI, everything after `where` is the query, and Tab completes field names.
- A malformed query says what's wrong and which fields exist.

Traffic log columns: `time rule action from to in out src sport dst dport
proto app len ttl flags icmp` (`from`/`to` are zones, `in`/`out`
interfaces). Without `columns`, the CLI shows time, rule, action, zones,
addresses, ports and protocol.

Both come from the systemd journal on the appliance, which keeps them across
reboots until it reaches its size limit (oldest first out).

## Upgrading

From 0.3.0 on, SJB-OS upgrades in place. Each release has a signed
`sjb-os-<version>.upgrade` bundle next to the OVA. It replaces the SJB-OS
programs and appliance files (ngfwd, fwctl, units, scripts) and nothing else:
config, revisions, tags, keys, certificates, passwords and network settings
stay as they are.

**From the web UI:** System → Administration → Upgrade, choose the `.upgrade` file, *Upload
and check* (the signature is verified before anything is installed), then
*Install*. The page reconnects when ngfwd is back; log in again.

**As root** (the operator CLI has no file transfer): copy the file over with
your root key (`root_ssh_key`) and run

```bash
fwctl upgrade verify sjb-os-0.4.1.upgrade   # optional: check it first
fwctl upgrade apply sjb-os-0.4.1.upgrade
fwctl upgrade status                           # version and history
```

`show version` in the CLI shows the version and history.

During an upgrade ngfwd restarts. The kernel keeps enforcing the running
ruleset meanwhile, so traffic is not interrupted. If ngfwd does not come back
answering with the same running revision within 30 seconds, the previous
files are put back automatically and the upgrade is reported as failed.
`fwctl upgrade rollback` as root (or the button on System → Administration) returns
to the version before the last upgrade.

The older version may not understand settings added since (DHCP servers,
application rules and groups). So if the config changed after the upgrade,
the rollback commits the config that was running at the upgrade again, as a
new revision, before the older version starts. Nothing is lost: the later
revisions stay in the history (`show revisions`, `show revision N`), and
`fwctl upgrade rollback` says which ones they are. An unchanged config is
left alone. Upgrades made with 0.7.0 or later save that config with the
backup; for older ones the rollback takes the last revision committed before
the upgrade.

Only bundles signed with the SJB-OS release key are accepted, and only
newer versions (`-reinstall` re-applies the installed one). Versions are
MAJOR.MINOR.PATCH with an optional suffix: `-rNN` is a revision build after
that release (0.6.1 counts as 0.6.1-r00, then r01, r02, ... compared as
numbers), and any other suffix, such as `-rc1`, comes before the release. The kernel and
Debian packages are not part of a bundle: keep them patched as root with
`apt update && apt upgrade` (the appliance reaches the Debian mirrors over
the outside link).

### Upgrading to 0.8.0 from an earlier version

0.8.0 renamed the product to SJB-OS. Upgrading an earlier appliance (0.3.0
or later) with `sjb-os-0.8.0.upgrade` moves it over in place:

- The admin login is renamed to **`admin`**, with the same password and SSH
  keys (SSH, console and web UI); commit history shows `admin` as the
  author.
- Files move to `/usr/share/sjb-os` and `/var/lib/sjb-os`; the services,
  banners, route protocol name (`proto sjb`) and os-release follow.
- Rolling back to the earlier version undoes the rename. The old names stay
  on disk until the next upgrade after 0.8.0, which removes them.
- The hostname isn't changed: it's in your config (`set system hostname`).
- Later bundles (0.8.0-r01 and on) install on 0.8.0 or newer only, so an
  older appliance goes through 0.8.0 first.

### Moving from 0.2.0 or earlier

0.2.0 and earlier have no updater: deploy a new OVA (vSphere 8.0 U1 or
later) and move the policy and tag registrations over:

1. On the old appliance, save the policy and tag registrations:
   ```bash
   sudo fwctl show running > running.yaml
   sudo cp /var/lib/ngfw/tags.json .
   ```
2. Deploy the new OVA with the same networks and settings.
3. Restore the policy through the new appliance's CLI, and the tags as root:
   ```bash
   ssh admin@<new-mgmt-ip> load < running.yaml
   ssh admin@<new-mgmt-ip> 'commit -m restore -confirm 5m'
   ssh admin@<new-mgmt-ip> confirm
   scp tags.json root@<new-mgmt-ip>:/var/lib/ngfw/ && ssh root@<new-mgmt-ip> systemctl restart ngfwd
   ```

Interface names are the same on every appliance, so configs move between them
unchanged. The full history lives in `/var/lib/ngfw/revisions/`.

## Troubleshooting

- **Console MACs don't match the vSphere adapters.** The NICs were mapped in a
  different order. Redeploy with adapter 1/2/3 on mgmt/inside/outside.
- **Can't reach mgmt.** Check the console for the mgmt address. Policy never
  filters mgmt, so this is addressing or port-group, not the firewall.
- **A commit broke something.** If it was committed with `-confirm`, wait for
  the rollback. Otherwise `show revisions` and `rollback N` in the CLI.
- **Inside clients can't get out.** Check their gateway and DNS, that outside
  has an address (`show interfaces`) and a default route (`show routes`),
  and `show ruleset`.
- **Outside has an address and route but nothing gets through.** `show arp
  outside`: the gateway should be `REACHABLE` with a MAC. `INCOMPLETE` or
  `FAILED` means the router isn't answering at Layer 2 (check the outside
  port group: connected, right VLAN, not 4095 unless you use VLANs).
- **A route says its gateway "isn't on a connected network".** No interface
  in that VRF has an address on the gateway's network: usually outside has
  no address (DHCP got no lease). Set one; see
  [Interface addresses](#interface-addresses).
- **Locked out of the CLI.** Log in as root with your root key, or as root
  on the VMware console, and reset `admin` with `fwctl web-passwd`. With no
  root access set up, see the recovery steps in [Root access](#root-access).

## Limits

- Runs in real use on ESXi; every release is also tested in QEMU with
  VMware's device models.
- IPv4 only. The management default route comes only from the deployment
  settings.
- App Identification rules can't use nDPI's risk scores yet. The IPS has no per-profile
  exceptions yet, and blocks by dropping (no reset).
- The web UI and tag API certificate is self-signed (`curl -k`).
- One web UI user (`admin`); no roles yet.
- Upgrades cover SJB-OS itself and the packages it ships (FRR, Kea,
  App Identification's libraries), not
  the kernel or other Debian packages (apt).
- `admin` can log in over SSH with a password. For anything beyond a lab,
  set `admin_ssh_key` at deploy time and use a strong password.
- No root key or password ships with SJB-OS; root has only what you set at
  deploy time.
- Some admin tasks (API key edits, logs, Debian updates) still need root;
  they move into the CLI over time.

## Building the OVA

For maintainers. From the repo root:

```bash
nix develop                               # or any shell with Go 1.26+
VERSION=0.3.1 deploy/appliance/build.sh
```

Output: `build/appliance/sjb-os-<version>.ova`, the signed
`sjb-os-<version>.upgrade` bundle, and a `.raw` disk for boot tests.

The bundle is signed with the release key at
`~/.config/sjb-os/upgrade-signing.key` (override with `SIGNING_KEY=`); its
public half is `rootfs/usr/share/sjb-os/upgrade-keys/sjb-os-release.pub`,
baked into every image. Without the private key the build skips the bundle.
Keep the key backed up (for example in 1Password): appliances only accept
bundles it signed, so losing it means the next release needs a redeploy. To
rotate it, ship a bundle signed with the old key that adds the new `.pub`.

Release images carry no root key. For your own lab images,
`ROOT_KEY_FILE=~/.ssh/id_ed25519.pub` bakes that key into
`/etc/ngfw/root_authorized_keys` (the build warns, and such an image must
never be published); without it the build checks that the image has no root
key at all. Needs Docker with linux/amd64 support (OrbStack or Docker Desktop
on Apple Silicon). The first build downloads Debian's generic cloud image
(about 400 MB) and checks its SHA-512.

Before handing out a build, boot-test it:

```bash
deploy/appliance/boot-test.sh build/appliance/sjb-os-<version>.raw
```

This boots the disk in QEMU with VMware's pvscsi disk controller and vmxnet3
NICs and runs 80 checks: first boot, the tag API, the captive CLI and root access
(including configuration mode: set, move, commit, rename, delete)
(shell and sudo refused, no file transfer, root key only), one password
(changed in the web UI, then with the CLI's `passwd`), static routes
(installed in both tables, put back after deletion, removed), VRFs and VLAN
subinterfaces (overlapping addresses, conntrack zones, VRF and leak routes,
self-healing, removal, a VRF client blocked from the firewall), BGP and OSPF against a peer router in a network
namespace (FRR installed from the bundle, sessions up, routes both ways,
firewall openings, UI and CLI views), both logs in
the web UI and the CLI, a pending
commit surviving an ngfwd restart and then rolling back, the web UI (login,
adding a rule, commit-confirm), upgrades (a good bundle from the UI, a
tampered one, a broken one that must roll itself back, `fwctl upgrade
rollback`) and apt. Needs qemu, sshpass, curl, python3, Go and the signing
key; run it inside `nix develop`. The test gives the VM a throwaway root key
and console password for each run, through QEMU's firmware config, as an
operator would at deploy time (base images from before 0.9.9 use their
built-in key instead, from the SSH agent).

`boot-test.sh OLD.raw NEW.upgrade` upgrades the image to the bundle right
after first boot, then runs every check against the new version: the test
for bundle-only builds (`BUNDLE_ONLY=1 VERSION=x.y.z deploy/appliance/build.sh`),
which skip the OVA.

Given an older image and a bundle, `boot-test.sh OLD.raw NEW.upgrade`
upgrades it first and tests the new version; from an image before 0.8.0 it
also checks the move to the SJB-OS names, rolls back to the image's version
(the account gets its old name back) and upgrades again.

What goes into the image: `rootfs/` is copied over the root filesystem
(systemd units, first-boot and console scripts, sysctl and sshd settings,
the upgrade signing key); the same overlay plus the binaries is what an
upgrade bundle carries;
`build-image.sh` installs packages, removes cloud-init, masks
`nftables.service` (it would flush ngfwd's ruleset) and adds the VMware
storage drivers to the initramfs; `sjb-os.ovf.in` is the OVF template.
