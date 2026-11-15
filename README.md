# hobby-ngfw (SJB-OS)

A next-generation firewall built by one person with Claude Code, as a
demonstration: App Identification, tag-driven dynamic address groups via API, inline IPS,
and a commit/rollback config model. It ships as a VMware appliance called
**SJB-OS**: Stops Junk at the Border.

**This is not a product.** The point is to measure how far AI-assisted
development compresses the *build* of a system that once took large vendor
teams years. Day-2 work (signature content, support, certification, long-term
maintenance) is explicitly out of scope. See
[docs/architecture.md](docs/architecture.md) for the design and
[docs/effort-log.md](docs/effort-log.md) for how it was built, release by
release, with the human hours behind each.

> I intentionally did not write, or even look at, a single line of code
> during this whole process. That isn't a good idea, and it isn't how a real
> software design process should ever work. It's simply an example of where
> we are today.
>
> Steve Boyle, SJB Consulting

Steve set the direction, made the design calls and tested the results;
[Claude Code](https://claude.com/claude-code) wrote the code, the tests and
the documentation.

## Deploying

The SJB-OS OVA is the only supported way to run hobby-ngfw. Deploy it on
vSphere 8.0 U1 or later with three networks: **mgmt**, **inside** and **outside**.

1. Download the OVA from [Releases](https://github.com/stevejboyle/hobby-ngfw/releases)
   (or build it, below) and check its `.sha256`.
2. In vSphere, **Deploy OVF Template** and map Network adapter 1 → mgmt,
   2 → inside, 3 → outside.
3. Fill in the deployment settings (vCenter), or set `guestinfo.ngfw.*`
   advanced settings (standalone ESXi), or accept the defaults.
4. Power on. The console shows the SJB-OS mark, the addresses and "SJB-OS ready: standing guard at the border."
5. Open the web UI at `https://<mgmt-ip>/` and log in as `admin` with the
   password from the console, or `ssh admin@<mgmt-ip>` for the CLI.

As on most enterprise firewalls, operators get a CLI, never a Unix shell: `admin` has no bash and
no sudo. Root logs in only with the SSH key or console password you set at
deploy time, for recovery; no root key or password ships with SJB-OS.

Later releases install in place: upload the signed `.upgrade` file on the web
UI (System → Administration).

The full guide, with settings, first-boot behaviour and day-to-day use, is
[deploy/appliance/README.md](deploy/appliance/README.md).

Once it's up, quarantine a host from anything that can reach mgmt, including
NAC, SOAR and EDR integrations that send XML user-ID messages:

```bash
curl -k -H "X-API-Key: $KEY" -d '{"ip":"10.10.1.50","tags":["quarantine"],"ttl":3600}' \
  https://<mgmt-ip>:8443/api/v1/tags/register
```

## Status

Phase 1 gate passing: commit/rollback/commit-confirmed, zones and rules
compiled to nftables, masquerade NAT, tag → IP API (REST, plus XML user-ID
`uid-message` for existing integrations) applying in about 20 ms, restart recovery, packaged as an OVA.
Pulled forward from phase 3: a web UI with form-based policy editing, signed
in-place upgrades with automatic restore, a captive CLI in place of shell
access with a configure-and-commit mode and Tab completion, and routing as
part of the commit: static routes, VRFs with VLAN subinterfaces, BGP and
OSPF (FRR). It runs in real use on ESXi, and every release is also tested
in QEMU with VMware's device models. Phase 2 so far: traffic and system
logs with queries, a DHCP server, and App Identification with application policy,
groups and categories, and IPS (Suricata with Emerging Threats Open,
per-rule profiles, a threat log).

| Phase | Weeks | Gate |
| --- | --- | --- |
| 0 · Lab, skeleton | 1–2 | One command builds and tests the lab |
| 1 · Stateful core | 3–6 | Tag API blocks a host in under 1 s; rollback restores |
| 2 · NGFW features | 7–11 | PCAP suite passes: apps denied by name, test signatures drop |
| 3 · Polish and HA | 12–16 | Failover keeps sessions; 1 Gbps with IPS on |

Effort is tracked in [docs/effort-log.md](docs/effort-log.md).

## Building the OVA

```bash
nix develop                               # or any shell with Go 1.26+
VERSION=0.4.0 deploy/appliance/build.sh   # -> sjb-os-0.4.0.ova and .upgrade
```

Needs Docker with linux/amd64 support (OrbStack or Docker Desktop on Apple
Silicon). Details in [deploy/appliance/README.md](deploy/appliance/README.md#building-the-ova).

## Developing

Unit tests and the end-to-end gates run on every push in CI. The gates use a
network-namespace lab, which is a test harness only, not a way to deploy.

```bash
make test            # vet and unit tests
make validate        # check example configs
```

See [CLAUDE.md](CLAUDE.md) for layout, conventions and how to run the gates
from a Mac.

## Built on

nftables and conntrack (Linux), Debian 13, [nDPI](https://github.com/ntop/nDPI)
and [Suricata](https://suricata.io) (phase 2), ClickHouse, keepalived and
conntrackd (phase 3).

## Contributing and security

Issues are welcome, especially bugs and ideas. As a demonstration with one
maintainer, pull requests may not be merged. To report a security problem,
see [SECURITY.md](SECURITY.md); please don't open a public issue for it.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
appliance image and upgrade bundles also contain third-party software under
its own licenses, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

SJB-OS is a demonstration, not a supported product, and comes with no
warranty.
