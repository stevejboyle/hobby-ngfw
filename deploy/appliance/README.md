# SJB-OS appliance guide

SJB-OS exists to show how far one person can get building systems software
by directing AI instead of writing code (see the repo's README for the goal
and the evidence). This guide is for trying it in a lab.

**An experimental demonstration of AI-generated software for isolated lab
use. Not a commercial, supported, or production-ready security product. Do
not rely on it to protect production systems. Working code does not
establish security effectiveness, resilience, or operational readiness.**
Its project-specific code was generated with Claude Code under Steve Boyle's
direction and reviewed with ChatGPT's help; it relies on Linux netfilter,
nDPI, Suricata, FRRouting, Kea and Debian for the real work (see the repo's
README).

SJB-OS (Stops Junk at the Border) is a
firewall packaged as a VMware OVA, and that is the only supported way to run
it. The VM is Debian 13 with ngfwd, nftables and open-vm-tools: 3 vmxnet3
NICs, 2 vCPU, 2 GB RAM, 8 GB disk. Give it 4 GB of RAM to use the IPS.

## Before you start

- The OVA from [Releases](https://github.com/stevejboyle/sjb-os/releases),
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
   | hostname | sjb-fw | Change it later with `set system hostname NAME` and commit: the prompt, web UI and console follow (0.9.9-r08 and later) |
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
- User `admin`, the permanent superuser, whose login (SSH and console) is
  the SJB-OS CLI, not a Unix shell, and who has no sudo. SSH host keys, a
  self-signed TLS certificate (web UI and tag API; replace it with your own,
  see [Management certificate](#management-certificate)), a tag API key, and one
  password for `admin` that works for SSH, the console and the web UI. Add
  more users, each with a role, later (see [Users and roles](#users-and-roles)).
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
Log forwarding, Revisions, Backup, Certificate, Administration).

- **Policy, NAT, Objects, Interfaces:** add, edit, delete and reorder security
  rules, NAT (port forwarding, static NAT, source NAT, with live connection
  counts), addresses, address groups (static or tag-based),
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
- **Revisions:** every commit with its author (`web:alice` from the UI,
  `cli:alice` from the CLI: the firewall records who was logged in, not what
  a client claims), view the config of any revision, roll back.
- **Logs:** the data-plane (traffic) and management (system) logs; see
  [Logs](#logs).
- **Log forwarding:** syslog servers (a SIEM) the logs go to, with their
  status and a test button; see
  [Forwarding logs to a SIEM](#forwarding-logs-to-a-siem).
- **Backup:** download a backup, restore one; see
  [Backing up and restoring the configuration](#backing-up-and-restoring-the-configuration).
- **Certificate:** the web UI and tag API certificate: import your own, or
  go back to self-signed; see [Management certificate](#management-certificate).
- **Administration:** upgrades (below).
- **Users** and **Roles** (superusers): see [Users and roles](#users-and-roles).
- **My account** (top right): your password, your SSH keys and what your
  role allows.

Each user has one password for the web UI, SSH and the console. Change
yours on My account or with `passwd` in the CLI; either changes all three.
Five wrong passwords in a row lock the account for 15 minutes; after five
wrong passwords from one address, logins from it are also refused for a
while (15 seconds, doubling up to 15 minutes). Sessions end after 8 hours
idle, when ngfwd restarts, and at once when the user is disabled, deleted
or has their password changed. Pages and buttons your role can't use are
hidden; the firewall refuses those calls anyway.

Saving from the UI rewrites the candidate YAML, so comments in it are not
kept.

## Management certificate

The web UI (port 443) and the tag API (port 8443) present one certificate.
First boot makes it self-signed, so browsers warn and API clients need
`curl -k`. To stop that, import a certificate your clients trust, for
example one your lab CA issues for the firewall's name or management
address:

- **Web UI:** System → **Certificate**: paste (or load from files) the
  certificate, then the intermediates that issued it in order (not the
  root), and its private key.
- **CLI:** `request management-certificate import`, then paste the same,
  as the prompts ask (finish the certificates with a line `end`).

The firewall checks that the certificate comes first and each intermediate
signed the one before it, that the key belongs to it and isn't encrypted,
that it is ECDSA or RSA of 2048 bits or more, that it is valid now, and
that it is for a server (not a CA; server authentication allowed). It
warns, but accepts it, when it names neither the hostname nor the
management address, when no chain was given for a certificate a CA issued,
or when it expires within 30 days.

New connections get the new certificate at once, with no restart. Open
ones, including the page you imported from, keep the old one until they
reconnect, so the import never cuts you off. If a client doesn't trust it,
a new tab shows the warning: `request management-certificate self-signed`
(or **Back to self-signed** on the page) makes a fresh self-signed
certificate naming the hostname and the management address.

`show management-certificate` (and the page) shows the subject, issuer,
names (SANs), validity, chain and SHA-256 fingerprint; `show
management-certificate pem` adds the certificate. The files live in
`/etc/ngfw` (`tls.crt`, `tls.key`, mode 0600), never in the config,
a backup or an upgrade bundle, and upgrades leave them alone. Importing
needs the `certificates` permission (superusers and the `admin` role).
There is no ACME (automatic renewal) yet: import a new certificate before
the old one expires.

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
the mgmt address as your user (or log in on the VMware console) and you get
the `<user>@<hostname>>` prompt. There is no bash, no sudo, no file transfer and
no port forwarding. `help` lists the commands your role can use (Tab and ?
show the same):

| Command | What it does |
| --- | --- |
| `show status`, `show version` | Running revision, pending confirm; SJB-OS version and upgrade history |
| `show running`, `show candidate`, `show diff` | The config as YAML, and what changed |
| `show ruleset`, `show revisions`, `show revision N` | Compiled nftables ruleset; commit history; an old config |
| `show tags [TAG]`, `show interfaces`, `show api-keys` | Registrations, addresses, tag API keys |
| `show arp [INTERFACE]` | ARP table: which neighbours answered, with their MACs |
| `show routes [vrf NAME]` | Static routes from the config (installed or not, and why), then the routing tables: default, each VRF, mgmt |
| `show nat` | NAT entries (port forwards, static NAT, source NAT) with the connections each has translated, and hairpinned |
| `show management-certificate [pem]`, `request management-certificate import\|self-signed` | The web UI and tag API certificate; import your own or go back to self-signed (see [Management certificate](#management-certificate)) |
| `show vrf` | VRFs with their table, interfaces and state |
| `show bgp`, `show ospf` | BGP neighbors (state, uptime, prefixes) and OSPF neighbors, every VRF |
| `show rib [vrf NAME]` | The routing table as FRR sees it, with the protocol of each route |
| `show app`, `show app catalog [TEXT]`, `show app categories` | Applications App Identification has seen (connections, bytes); every application it can identify; its categories |
| `show dhcp`, `show dhcp leases [INTERFACE]` | DHCP servers (range, gateway, DNS, active leases); the leases handed out |
| `load` | Paste a whole config (YAML), end with a line `end` |
| `revert` | Discard uncommitted changes |
| `commit [-m "MSG"] [-confirm 5m]`, `confirm`, `rollback N` | Apply, accept, go back |
| `tags register IP TAG... [-ttl 1h]`, `tags unregister IP TAG...` | Tag hosts |
| `show whoami`, `show ssh-keys` | Your user, role and what it allows; your SSH keys |
| `ssh-key add`, `ssh-key delete N` | Add (paste) or delete your own SSH keys |
| `show users`, `show user NAME`, `show roles`, `show role NAME` | Users and roles (superusers) |
| `request user ...`, `request role ...` | Add, change and delete users and custom roles (superusers; see [Users and roles](#users-and-roles)) |
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
[`examples/best-practice.yaml`](../../examples/best-practice.yaml) is a
starting point for a secure policy: default deny with an outbound
allow-list, the IPS on every allowed connection, risky applications
blocked, tag-based quarantine, and TLS decryption of users' web traffic
with sensible exclusions. It has no network settings of its own, and
`load` replaces the whole config, so merge it with yours rather than
loading it bare. Then [`tools/policy-test.sh`](../../tools/policy-test.sh),
run from a client in the inside zone, checks the policy is enforced:
allowed services work; other ports, resolvers and encrypted DNS don't get
out; the IPS blocks its test strings over HTTP and decrypted HTTPS; sites
are decrypted, exclusions aren't, bad certificates and QUIC are blocked.
Each "blocked" result is checked against a working control, so it means
the firewall stopped it. `-D` gives it your approved DNS resolvers.

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
- **Trunks (0.9.10-r02):** when inside or outside only carries VLANs, give
  it no zone and no address (`delete interface inside zone`, or
  `- name: inside` alone in YAML). It becomes a trunk: SJB-OS drops
  everything untagged on it, to the firewall and through it, whatever the
  rules say, and takes the deployment's address (`inside_ip`, or DHCP) off
  it; put it back in a zone and the deployment's settings return. A trunk
  needs at least one VLAN subinterface, can't be in a VRF or publish a NAT
  entry, and shows as "trunk" on the Interfaces page and in
  `show interfaces`.

  ```yaml
  interfaces:
    - name: inside          # the trunk: VLANs only
    - name: inside.150
      zone: inside
      address: 192.168.150.1/24
    - name: inside.151
      zone: dmz
      address: 192.168.151.1/24
  ```
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
- **Interfaces you didn't create:** with TLS decryption set up, `show arp`
  and root's `ip link` also list `sjbd-c` and `sjbd-s`. They are the two
  ends of decryption's internal cleartext loop (see
  [How it works](#how-it-works)), with link-local addresses (169.254.77.x)
  that never leave the appliance. Nothing to configure; ngfwd creates and
  removes them with decryption.

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

## Publishing servers (port forwarding and static NAT)

Inside traffic going out is NATed to the outside address (source NAT,
`type: masquerade`). To let the internet reach a server behind SJB-OS, add a
port forward or a static NAT entry to the same `nat` list: on the web UI's
Security → NAT page (sections **Port forwarding**, **Static NAT** and
**Source NAT**), in configure mode, or in YAML.

- **Port forward:** a public port (or range) on the arrival interface goes
  to a port on one inside server. Without a public address it uses the
  interface's own address, whatever it is (DHCP included).
- **Static NAT (1:1):** every port of a public address goes to one inside
  server. It is **bidirectional** unless you turn that off: the server's own
  outbound connections leave from its public address instead of the shared
  outside address.

```yaml
addresses:
  - name: web-server
    cidr: 172.16.40.10        # the server's inside address
  - name: mail-server
    cidr: 172.16.40.25
  - name: mail-public
    cidr: 198.51.100.25       # an extra public address from your provider
nat:
  - name: web
    type: port-forward
    interface: outside
    protocol: tcp
    public_port: "443"        # or a range, e.g. 8000-8010 (same range on the server)
    server: web-server
    server_port: "8443"       # optional; default: the public port
  - name: mail
    type: static
    interface: outside
    public_address: mail-public
    server: mail-server
    # bidirectional: "off"    # inbound only
rules:
  - name: web-in
    from: [outside]
    to: [dmz]
    destination: [web-server] # the inside address, not the public one
    service: [web-alt]        # tcp 8443: the server's port
    action: allow
    log: true
    ips_profile: default
```

In configure mode:

```
set address web-server cidr 172.16.40.10
set nat web type port-forward interface outside protocol tcp public-port 443 server web-server server-port 8443
set nat mail type static interface outside public-address mail-public server mail-server
```

**NAT only translates; a security rule still has to allow the traffic.**
SJB-OS translates published traffic as soon as it arrives, so everything
after that sees the server's real address and port: the security rules, App
Identification, the IPS, TLS decryption and the logs. Write the allow rule
with the server's **inside** address and the zone it sits in, and its port on
the server (8443 above, not 443). A commit warns about a published server
that no allow rule lets in. Give published servers an IPS profile and
logging, as `examples/best-practice.yaml` shows.

Public addresses and the server must be address objects naming one host.
SJB-OS answers for an extra public address on the arrival interface (it adds
it there when you commit, removes it when you delete the entry, and puts it
back within about 10 seconds if it goes missing); nothing on the firewall
itself listens on it. Pings to it reach the firewall and other ports are
dropped, unless a static NAT entry sends everything to the server. A port
forward on the interface's own address doesn't catch the extra addresses.
The management address can't be published.

`show nat` (or the NAT page) lists every entry with the connections it has
translated, and says if an extra public address isn't on its interface yet.
To check from outside, run `tools/policy-test.sh -I <public-address>:<port>`
on a machine on the internet side: the published port should answer and the
others shouldn't.

Things to know:

- **Same VRF.** The server must be in the VRF of the interface the traffic
  arrives on; the commit refuses one in another VRF.
- **Decryption.** A decryption rule that matches published traffic
  decrypts it, as it would outbound traffic, and visitors then see the
  SJB-OS decryption CA's certificate, which their devices don't trust. Only
  useful in a lab; write decryption rules for outbound traffic.
- **Hairpin NAT** is on for every entry unless it says `hairpin: "off"`;
  see below.
- Order matters only among entries of the same kind: `move nat NAME ...`
  (or the arrows on the NAT page) reorders them.

### Hairpin NAT

Clients on SJB-OS's other interfaces (inside, a DMZ, VLANs) can also reach
a published server by its **public** address, so the same name works inside
and out. Each port forward and static NAT entry is published this way too,
unless you turn it off:

```yaml
nat:
  - name: game
    type: port-forward
    interface: outside
    public_address: game-public
    protocol: udp
    public_port: 27015-27020
    server: game-server
    hairpin: "off"            # outside only; inside clients use the inside address
```

`set nat game hairpin off` in configure mode, or untick **Hairpin** on the
NAT page.

- **The rules still decide**, as for any inside traffic. A hairpinned
  connection is judged from the client's zone to the server's zone, with the
  server's inside address and port. In `examples/nat.yaml`, rule
  `inside-to-web` (from inside to dmz, destination `web-server`, service
  `web-alt`) lets inside clients use the web server's public address. Without
  such a rule they are dropped like any other inside-to-DMZ traffic.
- **The server sees the real client address**, except for clients on the
  server's own network. Their replies would go straight back without passing
  the firewall, so SJB-OS gives those connections its own address on that
  network (masquerade).
- Which interfaces: every zoned interface in the published interface's VRF
  (the server's) except the published interface itself. Never mgmt.
- A port forward on the interface's own address follows that address. For
  one from DHCP or the deployment settings, SJB-OS keeps the current address
  in the ruleset (set `ifaddr_<interface>`), updated within about 10 seconds
  of a change.
- `show nat` and the NAT page count hairpinned connections separately
  (**Hairpin** column).
- Hairpinned HTTPS is decrypted if a decryption rule matches it (from the
  client's zone to the server's), like any other connection.

## Users and roles

Every person who manages the firewall gets their own user. A user has one
password for the web UI, SSH and the VMware console, optional SSH keys, and
one role. Their SSH and console logins land in the CLI, never a shell, like
`admin`'s. The firewall works out who is calling itself (the logged-in Unix
user behind each CLI command, the web session's user) and checks every
command and click against that user's role as it is now: changing a role,
disabling a user or deleting one takes effect at once.

**Built-in roles:**

| Role | May |
| --- | --- |
| `superuser` | Everything: users and roles, upgrades, the decryption CA, tag API keys, and all the below |
| `admin` | See everything except secrets; change and commit the config (log forwarding included), roll back, confirm, tags, IPS signature updates, the management certificate, config-only backups and restores |
| `read-only` | See everything except secrets (tag API keys); change nothing |

`admin` (the user) is a permanent superuser: it can't be deleted, disabled
or given another role. Nobody can disable, delete or change the role of
their own account.

**Custom roles** pick, per area, none, view or change:

| Area | Covers |
| --- | --- |
| `policy` | Rules, addresses, address groups, services, application groups, zones, NAT, App Identification on/off |
| `network` | Interfaces, static routes, VRFs, BGP/OSPF, prefix lists, the hostname |
| `dhcp` | DHCP servers, reservations and leases |
| `ips` | IPS profiles and exceptions, on/off, disabled signatures; signature updates |
| `decryption` | Decryption rules, profiles and exclusions; the learned list |
| `decryption-ca` | The decryption CA: generate or import |
| `certificates` | The management certificate (web UI and tag API): import, or back to self-signed |
| `logging` | Log forwarding: the syslog servers (a SIEM) the logs go to |
| `tags` | Tag registrations |
| `monitoring` | Logs, statistics, applications, ARP, routing status, ping (view only) |
| `revisions` | Commit history; change: confirm a commit, roll back |
| `upgrades` | SJB-OS upgrades and upgrade rollback |

Users and roles themselves are for superusers only; no custom role can be
given them. A role with view on any config area sees the whole config (it
holds no secrets). Config changes are checked by area: an edit, `load`,
`revert`, commit or rollback that touches an area the role can't change is
refused, naming the area. The candidate is shared, so a commit carries
everyone's pending edits: if someone else's change touches an area you
can't change, your commit is refused until a user who can commits or
discards it.

**In the web UI:** System → Users (add, edit role, disable, set a
password, unlock, SSH keys, delete) and System → Roles (built-in roles to
view; custom roles as an area-by-access grid).

**In the CLI** (superusers):

```
admin@sjb-fw> request user add alice role admin
New password for alice (10+ characters):
Again:
admin@sjb-fw> request role add policy-editor description "rules and objects"
admin@sjb-fw> request role set policy-editor policy change
admin@sjb-fw> request role set policy-editor revisions view
admin@sjb-fw> request user set bob role policy-editor
admin@sjb-fw> request user set carol disabled yes
admin@sjb-fw> request user password alice
admin@sjb-fw> request user unlock alice
admin@sjb-fw> request user ssh-key add alice      (then paste the key)
admin@sjb-fw> request user delete carol
admin@sjb-fw> show users
admin@sjb-fw> show role policy-editor
```

Everyone can see their own role (`show whoami`), change their password
(`passwd`) and manage their own SSH keys (`ssh-key add`, `ssh-key delete N`,
`show ssh-keys`, or My account in the web UI). Keys work for SSH straight
away; `admin_ssh_key` from the deploy settings becomes admin's first key.

**Lockout:** five wrong passwords in a row lock an account for 15
minutes. The web UI and SSH/console count separately (so up to five of
each). A superuser can unlock early (`request user unlock NAME`, or Unlock
on the Users page). Root is never locked, and `admin` is never locked on the
VMware console, so there is always a way in. There is no password expiry.

**Audit:** commits and rollbacks record the user (`cli:alice`,
`web:alice`, `root`); logins, failed logins, lockouts, tag changes, CA
changes, upgrades and every user and role change are in the system log
(`show log system`, Logs → System) with who did it.

**Upgrading and rolling back:** the first start after the upgrade turns
the old single user into `admin` the superuser, with the same password and
key; nothing changes for you until you add users. A rollback to an older
version (which knows only `admin`) locks every other user's login first, so
nobody gets more rights than their role allowed; upgrading again brings
them back as they were. Users and roles are kept apart from the config, so
a config rollback never brings back a deleted user or an old password.

Users are local to the appliance for now; signing in through a directory
(LDAP, RADIUS, SAML or OIDC) is planned for a later phase.

## Root access

Root is for recovery, not operations, and only you decide who has it: no
root key or password ships with SJB-OS, and the vendor has no way in.

- **SSH:** key only, with the key you set as `root_ssh_key` at deploy time
  (`ssh root@<mgmt-ip>`). It lives in `/etc/ngfw/root_authorized_keys`,
  which upgrades never touch; edit it there as root to add or change keys.
  Passwords are always refused for root over SSH.
- **VMware console:** root can log in with the `root_password` you set at
  deploy time (change it later with `passwd` as root).
- **Neither set:** root can't log in. To recover, from the VMware console:
  1. Restart the VM and interrupt the boot at the GRUB menu (hold Shift or
     press Esc). Press `e`, add `init=/bin/bash` to the end of the line
     starting with `linux`, and press Ctrl-X to boot. You get a root shell.
  2. The disk starts read-only: make it writable with
     `mount -o remount,rw /`.
  3. Fix what you need: reset `admin` with `fwctl web-passwd`, and consider
     adding a key to `/etc/ngfw/root_authorized_keys` so next time you can
     use SSH instead.
  4. Run `sync`, then restart the VM from vSphere (Reset). This shell
     can't shut down cleanly on its own.

  Anyone with that much access to vSphere could do the same.
- **Appliances from before 0.9.9** carried a development key. Upgrading
  moves that appliance's key to `/etc/ngfw/root_authorized_keys`, so its
  owner keeps access; new deployments never get it.

Root-only tasks for now: editing tag API keys (`/etc/ngfw/api-keys`, one
`<name> <scopes> <key>` per line, scopes `tags:read`/`tags:write`, keys of
24+ characters, then `systemctl restart ngfwd`), resetting a forgotten
password (`fwctl web-passwd -user NAME`, `admin` by default, which sets SSH,
console and web UI together, clears any lockout and takes effect at once, no
restart needed; superusers can do the same from the CLI or web UI), and Debian updates (`apt update && apt upgrade`). The full
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
- **False positives:** leave a signature out everywhere by its ID (from the
  threat log), `set system ips-disabled-signatures [ 2013504 ]`, or only
  where it misfires, with an exception (below).
- **Exceptions** stop one signature from blocking for part of the
  inspected traffic only: the traffic of some rules, from some clients
  (source) and/or to some servers (destination, by inside address as rules
  name them). Everything you give must match, and you must give at least
  one. **alert** (the default) still logs each match, with the exception's
  name in the threat log's Exception column, and **ignore** logs nothing.
  Add them on the **IPS** page (**Exceptions**) or:

  ```
  set ips-exception scanner-to-web sid 2019876 rule web-in source vuln-scanner destination web-server
  set ips-exception build-downloads sid 2027758 source build-hosts action ignore
  ```

  ```yaml
  ips_exceptions:
    - name: scanner-to-web
      sid: "2019876"
      rules: [web-in]           # rules with an IPS profile
      source: [vuln-scanner]    # the connection's client
      destination: [web-server] # its server's inside address
    - name: build-downloads
      sid: "2027758"
      source: [build-hosts]
      action: ignore
  ```

  `show ips` and the IPS page list them, with the packets each has let
  through. Up to 35 different signatures can have exceptions. The firewall
  decides them, not Suricata: it rebuilds the signatures when you add or
  remove one, and until Suricata has loaded them (a minute or so) the
  signature keeps blocking. When another signature matches the same packet,
  the profile decides as usual: an exception never hides a different match.
  Each signature with exceptions gets one of 35 internal codes, and a code
  that an earlier signature set gave another signature stays out of use
  until SJB-OS has had Suricata reload and seen it finish, so an old match
  can never pass as a new exception. If you swap many exceptions to other
  signatures in quick succession (or Suricata isn't answering), a new
  exception can find no code free: the commit warns, `show ips` and the IPS
  page mark it **inactive**, and its signature keeps blocking. Commit again
  once `show ips` reports the signatures loaded.
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
  each. It also checks TLS decryption (see below). `-l` lists everything
  without sending anything.
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
- Not yet: reset instead of drop, file and URL filtering, IPv6.

## TLS decryption

**Read this first.** TLS decryption puts the firewall in the middle of
encrypted connections. It is a powerful and intrusive feature:

- **Legal:** decrypting other people's traffic can be unlawful without
  their knowledge or consent. Wiretap, employee-monitoring and data
  protection laws differ by country and state. Decrypt only devices you own
  or run, for users who have been told. This is not legal advice.
- **Privacy:** while it passes them on, the firewall sees passwords,
  messages, health and financial details in the clear (in memory; nothing
  of the content is stored or logged). Exclusions reduce this; the built-in
  list is not complete.
- **Security:** anyone who has the decryption CA's private key can
  impersonate any website to every client that trusts the CA. The key sits
  unencrypted on the VM's disk (readable only by tlsd's account): VM
  snapshots, backups, clones and exported OVAs carry it, so protect them.
  The firewall becomes the judge of every decrypted site's certificate: it
  checks names, dates and chains against Debian's trusted roots, but does
  no revocation checking. tlsd is new, AI-written security code in an
  experimental lab appliance.

**Try it in observe mode first:** `set system decryption observe` reads
each connection's TLS hello, decides what it would do, logs that (`show log
decryption`) and passes every connection through unchanged, so you can see
what your rules and exclusions cover before anything is decrypted.
(0.9.9-r04 always observed; decryption itself arrived in 0.9.9-r05.)

### How it works

Decryption rules pick connections (by zone, address and TCP service; port
443 when no service is given). The firewall hands each new connection they
cover to **tlsd**, which reads the client's TLS hello (the server name) and
decides:

- **Excluded** (never decrypted): server names on SJB-OS's built-in list
  (banking, payment, health and government sites:
  `/usr/share/sjb-os/decryption-exclusions.txt`) and on your exclusion
  lists. A name covers itself and everything under it; `*.name` only what's
  under it.
- **Can't be decrypted**: not TLS, TLS older than 1.2, no server name,
  encrypted client hello (the real name is hidden), servers that won't do
  TLS 1.2 or later with the firewall. The rule's profile passes these
  through (default) or blocks them.
- **Decrypted**: tlsd connects to the real server and checks its
  certificate (offering HTTP/1.1 when the client offers it, which App
  Identification and the IPS read best; HTTP/2-only clients keep HTTP/2), then completes the client's connection with a certificate it
  issues for that server name, signed by the decryption CA (valid at most a
  week, made in memory). When the server's own certificate fails the
  checks (expired, self-signed, wrong name), tlsd issues one from a
  separate **untrusted** CA instead, so the browser shows its usual warning
  and the user decides, as without the firewall (or the profile blocks it).
- **Pinned apps**: an app that only accepts its server's own certificate
  rejects the firewall's. tlsd then remembers that server for 24 hours and
  passes it through from then on (`show decryption learned`); the first
  connection fails. The profile can block instead.

Whatever tlsd decides, the connection's bytes (decrypted, or as they came)
cross the firewall's normal rules again on an internal hop, so the
**security rules still decide what is allowed**, App Identification names
the application, and an allow rule's **IPS profile inspects the decrypted
content**; threat log entries for matches inside decrypted traffic say so
(`decrypted` column). QUIC (HTTP/3 over UDP 443) can't be decrypted: for
decrypted traffic it is blocked, so browsers fall back to TLS (a profile
can allow it).

The internal hop is a loop of two virtual interfaces, **`sjbd-c`** (the
client side: decrypted bytes enter the firewall here as if from the
client) and **`sjbd-s`** (the server side: they leave the forward rules
here for tlsd to re-encrypt towards the real server). Each has its far end
in a private network namespace of the same name and a link-local address
(169.254.77.x), and the loop has its own connection-tracking zone, so its
traffic is never confused with the real connection. They show up in `show
arp` and root's `ip link`; they take no configuration.

Nothing decrypted is logged. The decryption log has, per connection, the
rule, the decision and its reason, the server name, addresses and ports.

### Setting it up

1. **Make a CA.** `request decryption ca generate` (or **Generate CA** on
   Security → **Decryption**) makes a CA on the firewall; its key never
   leaves it. It is named "SJB-OS Decryption CA (*hostname*)" after the
   hostname in the running config (`sjb-fw` if none is set), and clients
   and browsers show that name, so set the hostname you want first
   (`set system hostname NAME`, commit); changing it later means
   generating the CA again and reinstalling it on the clients. To use your own PKI instead, import a CA certificate and its
   unencrypted key (a subordinate CA is best; paste its intermediates after
   it, in order, and SJB-OS sends them with every certificate it issues):
   `request decryption ca import` or **Import a CA**.
2. **Install the CA certificate on the clients** you will decrypt, as a
   trusted root: download it from the Decryption page, or copy it from
   `show decryption ca`, and check the SHA-256 fingerprint on each client.
   - Windows: Trusted Root Certification Authorities (Group Policy for many).
   - macOS: Keychain Access, System keychain, then set it to Always Trust.
   - iOS/iPadOS: install the profile, then turn on full trust under
     Settings → General → About → Certificate Trust Settings.
   - Linux: `/usr/local/share/ca-certificates/` and `update-ca-certificates`.
   - Firefox keeps its own store: import it there, or turn on
     `security.enterprise_roots.enabled`.
   - Android: most apps ignore user-installed CAs and will be learned as
     pinned.
3. **Add decryption rules** (Policy → **Decryption rules**, first match
   wins; anything unmatched isn't decrypted):

   ```
   set decryption-rule users-out from inside to outside action decrypt
   set decryption-exclusion our-bank domain [ *.bank.example pay.example ]
   commit
   ```

   ```yaml
   decryption_rules:
     - name: skip-printer          # no-decrypt exempts from the rules below
       source: [printer]
       action: no-decrypt
     - name: users-out
       from: [inside]
       to: [outside]
       action: decrypt             # service: [https] by default (TCP 443)
       profile: default
   decryption_exclusions:
     - name: our-bank
       domains: ["*.bank.example", pay.example]
   ```

4. **Profiles** (Objects → **Decryption profiles**) choose, per rule:
   `bad-certificate warn|block`, `unsupported pass|block`, `pinned
   exclude|block` and `allow-quic yes|no`. The built-in **default** warns,
   passes, excludes and blocks QUIC.

Check it: `show decryption` (or the Decryption page) shows the state, the
CA and its fingerprint, counts by decision, and learned servers;
`show log decryption` (Logs → **Decryption**) shows each connection, e.g.
`show log decryption where decision = learned`.

From a Linux client behind the firewall,
[`tools/fw-traffic-test.sh -t`](../../tools/fw-traffic-test.sh) checks
decryption end to end by looking at which CA signed each site's
certificate: that sites are decrypted and this client trusts the CA,
that excluded banking, payment, government and health sites are not
(add your own with `-x name`), that badssl.com's broken certificates get
the untrusted CA or are blocked, that a connection without a server name
passes through, that the IPS catches its test strings inside HTTPS, and
what happens to QUIC. For an imported CA, pass its certificate with `-C`.

- **States:** **decrypting**; **observing** (`set system decryption
  observe`: log only, pass everything through); **busy** (tlsd holds its
  limit of 4096 connections: new ones pass through undecrypted until it has
  room); **no-ca** (no CA yet: everything passes through); **unavailable**
  (tlsd not running); **off**.
- **Fail-open:** the firewall hands connections to tlsd only while it
  answers (checked every 2 seconds). If tlsd stops, new connections take
  the normal path, undecrypted, and are still filtered by the security
  rules (App Identification by server name, IPS on the encrypted traffic);
  connections tlsd held at that moment are cut. ngfwd starts it again.
- **Off:** `set system decryption off` stops tlsd and removes it from the
  path. `set system decryption-builtin-exclusions off` stops using the
  built-in list (not recommended).
- **Replacing the CA** (generating again, or importing) means every client
  needs the new certificate.
- **Sizing:** each decrypted byte is decrypted, encrypted again and
  inspected. Give the VM **4 vCPU** (a commit warns on fewer) and 4 GB of
  RAM. tlsd itself is light: in the development lab (a container on an
  Apple-silicon Mac, IPS off) it decrypted single HTTPS downloads at over
  10 Gbit/s and peaked at about 15 MB of memory with 8 downloads at once.
  That says little about a VMware VM with the IPS inspecting; on a VM the
  IPS and the vCPU count set the pace.
  [`tools/decrypt-perf.sh`](../../tools/decrypt-perf.sh) measures straight
  through, observe and decrypted on any Linux machine.
- **Not yet:** decryption in VRFs other than the default, inbound (server)
  decryption, client certificates (passed through), revocation checking,
  IPv6. Without a NAT rule, servers see the firewall's address, not the
  client's.

## Logs

Four logs, under System → **Logs** in the web UI and in the CLI:

- **Data plane (traffic):** one entry per new connection that matches a
  rule with logging on (`log: yes`, the Log box on the Policy page, or
  `set rule NAME log yes`): time, rule, action, zones and interfaces in and
  out, source and destination address and port, protocol, packet length,
  TTL, TCP flags, ICMP type, and the application (App Identification, phase 2: empty
  until then). Rules without logging, and traffic dropped by the final
  default deny, aren't logged.
- **Threats (IPS):** signature matches on rules with an IPS profile (see
  [Intrusion prevention](#intrusion-prevention-ips)).
- **Decryption (TLS):** what TLS decryption did with each connection its
  rules cover: decrypted, excluded, passed through, learned, blocked, and
  why (see [TLS decryption](#tls-decryption)). Never what was inside.
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

### Forwarding logs to a SIEM

SJB-OS can send all four logs to one or more syslog servers as they are
written: a SIEM, a log collector, or a plain syslog host. Each message is
RFC 5424 syslog (APP-NAME `sjb-os`, MSGID `TRAFFIC`, `THREAT`, `DECRYPT` or
`SYSTEM`, the appliance's hostname) with a JSON or CEF body. Up to eight
servers, each with its own choices:

| Setting | Values | Default |
| --- | --- | --- |
| `address` | The server's IPv4 address | (required) |
| `transport` | `tls`, `tcp` (both octet-counted, RFC 5425 / 6587) or `udp` (RFC 5426) | `tls` |
| `port` | 1-65535 | 6514 for TLS, 514 for TCP and UDP |
| `format` | `json` (the entry as the Logs page has it, plus `"log": "traffic"` and so on) or `cef` (`CEF:0\|SJB Consulting\|SJB-OS\|<version>\|...`) | `json` |
| `types` | Any of `traffic`, `threat`, `decryption`, `system` | all four |
| `vrf` | `mgmt` (the management network) or `default` (a server behind inside or outside) | `mgmt` |
| `facility` | `local0`-`local7`, `user`, `daemon`, `auth`, `authpriv`, `syslog` | `local0` |
| `server_name` | TLS: the name the server's certificate must carry | the address |
| `ca` | TLS: a CA certificate (PEM) the server's certificate must chain to | Debian's trusted roots |

Severity follows the entry: traffic `info` (allowed) or `notice` (denied),
threats by signature severity (critical `crit`, major `err`, minor
`warning`, informational `info`), decryption `warning` when blocked or
failed, system entries by their level. In CEF, the rule is `cs1`, zones
`cs2`/`cs3` (traffic), the IPS profile `cs2` and the signature ID the
event class (threats), and the server name `dhost` (decryption).

In the web UI, **System → Log forwarding**: add, edit and delete servers
(the changes go to the candidate; commit as usual), and see each server's
state, messages sent, queued and dropped, and its last error. **Send test**
sends one system message. In the CLI:

```
admin@sjb-fw> configure
admin@sjb-fw# set log-server siem address 192.168.1.50 server-name siem.example.net
admin@sjb-fw# set log-server siem ca "-----BEGIN CERTIFICATE----- MIIB... -----END CERTIFICATE-----"
admin@sjb-fw# set log-server soc address 192.168.1.51 port 1514 transport tcp format cef type threat
admin@sjb-fw# commit -m "send logs to the SIEM"
admin@sjb-fw# exit
admin@sjb-fw> show log-forwarding
Log forwarding: following the journal
SERVER  ADDRESS            TRANSPORT  FORMAT  VRF   LOGS                              STATE              SENT  QUEUED  DROPPED
siem    192.168.1.50:6514  tls        json    mgmt  traffic,threat,decryption,system  connected for 2m  412   0       0
soc     192.168.1.51:1514  tcp        cef     mgmt  threat                            connected for 2m  3     0       0
admin@sjb-fw> request log-forwarding test siem
```

The CA can be pasted on one line (spaces for line breaks) in configure mode;
`examples/logfwd.yaml` in the repository shows the YAML form.

How it behaves:

- Forwarding starts when the first server is committed, from that moment
  on (older entries aren't sent). ngfwd keeps its place in the journal
  (`/var/lib/ngfw/logfwd.cursor`), so after a restart, an upgrade or a
  reboot it sends what was written in between, and nothing twice.
- Each server has its own queue of 10,000 messages. While a server is
  down, ngfwd retries (every second at first, then up to every 30 seconds)
  and the queue fills; when it is full, the oldest messages are dropped and
  counted (`DROPPED`). UDP gives no delivery guarantee at all; use TLS or
  TCP where losing entries matters.
- A TLS server must present a certificate for `server_name` (or the
  address) that chains to `ca` (or a public CA). A wrong certificate shows
  as the server's last error, and nothing is sent to it.
- Servers on the management network are reached through the management
  VRF, like SSH. A server behind inside or outside needs `vrf: default`;
  traffic from the firewall itself isn't filtered by the rules.
- Logging a lot of traffic (every rule with `log: yes`) sends a lot of
  messages: one or two per connection.

## Backing up and restoring the configuration

A backup is one text file holding the running config, and optionally the
users, roles and tag API keys. It is plain text so it can travel through
the CLI's copy and paste as well as the web UI:

```
SJB-OS backup of sjb-fw, 2026-11-21T10:00:00Z, by web:admin: config and accounts, encrypted
-----BEGIN SJB-OS BACKUP-----
eyJoZWFkZXIiOnsiZm9ybWF0Ijoic2piLW9zLWJhY2t1cCIs...
-----END SJB-OS BACKUP-----
```

- **Config only:** anyone whose role can view every config area. Not
  encrypted unless you give a passphrase; a checksum catches a damaged
  file (but not a deliberate edit).
- **With users, roles and API keys:** superusers only, and always
  encrypted (AES-256-GCM, with a key made from your passphrase by
  PBKDF2-SHA256): the file then holds the API keys and both password
  hashes of every user (the web UI's and the login's), so keep it like a
  password. Without the passphrase it can't be restored.

**Back up:** System → **Backup** → Download backup (tick the accounts box
for users, roles and keys, and give a passphrase), or in the CLI:

```
admin@sjb-fw> request backup export            # config only
admin@sjb-fw> request backup export accounts   # asks for a passphrase twice
```

The CLI prints the backup; copy everything from the first line to the END
line into a file.

**Restore:** System → **Backup** → choose the file (or paste it) → Check
backup shows where it came from; pick what to restore and Restore. In the
CLI, `request backup restore` (config), `request backup restore accounts`,
or `request backup restore config accounts`, then paste the backup and
give the passphrase if it has one.

- **The config never goes straight onto the firewall.** It becomes the
  candidate, with the same checks as any edit: it must be valid on this
  version, and your role must be able to change every area it changes.
  You see the diff against the running config, then commit it as usual;
  the web UI offers a commit with a 10-minute confirm timer, and in the
  CLI use `commit -m "restore" -confirm 10m`, so a backup from another
  firewall (other interfaces, other addresses) rolls back on its own if
  you lose access. `revert` discards it.
- **Users, roles and API keys** (superusers) take effect at once: they are
  not part of the config's revisions, so a config rollback never undoes
  them. The backup's custom roles are added or replace those of the same
  name; its users are added or updated with their role, enabled or
  disabled state, SSH keys and passwords (the same passwords work on SSH,
  the console and the web UI); users the backup doesn't have are kept,
  and `admin` and the user restoring are left as they are. The tag API key
  file is replaced and the new keys work at once. Restored users' sessions
  end.
- A backup from a newer SJB-OS whose format or config this version can't
  read is refused; upgrade first.

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

### Appliances older than 0.8.0

Bundles install on 0.8.0 or newer. An older appliance can't be upgraded in
place: deploy a new OVA (vSphere 8.0 U1 or later) and move the policy and
tag registrations over:

1. On the old appliance, save the policy (`show running`) and, as root, the
   tag registrations (`/var/lib/ngfw/tags.json`).
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
- **Locked out of the CLI.** If another superuser can log in, they can
  unlock you or set your password. Otherwise `admin` can always log in on the
  VMware console, or log in as root with your root key (or on the console)
  and reset a password with `fwctl web-passwd -user NAME`. With no
  root access set up, see the recovery steps in [Root access](#root-access).

## Limits

- Runs in real use on ESXi; every release is also tested in QEMU with
  VMware's device models.
- IPv4 only. The management default route comes only from the deployment
  settings.
- A published server must be in the same VRF as the interface its traffic
  arrives on; hairpin NAT reaches it from that VRF only.
- App Identification rules can't use nDPI's risk scores yet. The IPS blocks by
  dropping (no reset); at most 35 signatures can have exceptions, and an
  exception that finds no free code stays inactive until a later commit.
- TLS decryption is meant for outbound connections in the default VRF (it
  decrypts published servers' traffic only if a rule says so, and visitors
  then get certificate warnings), with no revocation checking; decrypted web traffic uses HTTP/1.1 where the client
  allows it.
- The web UI and tag API certificate is self-signed (`curl -k`) until you
  import your own; there is no ACME (automatic certificates) yet.
- Users are local to the appliance: no LDAP, RADIUS, SAML or OIDC yet. The
  web UI and SSH/console count failed logins separately.
- Upgrades cover SJB-OS itself and the packages it ships (FRR, Kea,
  App Identification's libraries), not
  the kernel or other Debian packages (apt).
- Users can log in over SSH with a password. For anything beyond a lab, give
  each user an SSH key and a strong password.
- No root key or password ships with SJB-OS; root has only what you set at
  deploy time.
- Some admin tasks (API key edits, logs, Debian updates) still need root;
  they move into the CLI over time.
- Log forwarding sends what is written from the first commit of a server
  on, with a per-server queue of 10,000 messages (dropped oldest first,
  and counted); no store-and-forward to disk, no RELP. Servers are IPv4
  addresses, not names.
- Restoring users and roles merges (it never deletes a user or role) and
  applies at once; only the config restore goes through commit and
  rollback.

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
upgrades it first and tests the new version, rolls back to the image's
version after a commit (the config running at the upgrade comes back) and
upgrades again.

What goes into the image: `rootfs/` is copied over the root filesystem
(systemd units, first-boot and console scripts, sysctl and sshd settings,
the upgrade signing key); the same overlay plus the binaries is what an
upgrade bundle carries;
`build-image.sh` installs packages, removes cloud-init, masks
`nftables.service` (it would flush ngfwd's ruleset) and adds the VMware
storage drivers to the initramfs; `sjb-os.ovf.in` is the OVF template.
