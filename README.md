# hobby-ngfw (SJB-OS)

**An experimental demonstration of AI-generated software for isolated lab
use. Not a commercial, supported, or production-ready security product. Do
not rely on it to protect production systems. Working code does not
establish security effectiveness, resilience, or operational readiness.**

SJB-OS ("Stops Junk at the Border") is a firewall appliance for VMware built
without manually writing code: zone-based policy compiled to nftables,
application identification with nDPI, inline intrusion prevention with
Suricata, host tagging through an API, routing and DHCP, managed with a
commit/rollback configuration model from a web UI and a CLI. The point is to
see how far AI-assisted development goes in building such a system, not to
offer one. Everything that makes a security product trustworthy beyond
working code (independent testing, threat research and signature content,
performance engineering, support, certification, long-term maintenance) is
out of scope. See [docs/architecture.md](docs/architecture.md) for the
design and [docs/effort-log.md](docs/effort-log.md) for how it was built,
release by release, with the human hours behind each.

Steve Boyle used Claude Code to generate the project-specific implementation,
tests, and documentation under his direction. He also used ChatGPT to review
the code and help optimize and finalize the solution, including identifying
correctness gaps and defining release-readiness fixes. Steve supplied the
architecture, requirements and decisions, and tested the results on his own
appliances.

> I intentionally did not write, or even look at, a single line of code
> during this whole process. That isn't a good idea, and it isn't how a real
> software design process should ever work. It's simply an example of where
> we are today.
>
> Steve Boyle, SJB Consulting

That statement is about Steve's own work: the code was still reviewed, by
AI (ChatGPT) and by the automated tests and boot tests described below.

The heavy lifting happens in established open-source software that SJB-OS
configures and ties together: the Linux kernel's netfilter (nftables,
conntrack, NFQUEUE), nDPI, Suricata with the Emerging Threats Open
signatures, FRRouting, ISC Kea, OpenSSH and Debian. Their authors deserve
the credit for what they do; see [Built on](#built-on).

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

Operators get a CLI, never a Unix shell: `admin` has no bash and no sudo. Root logs in only with the SSH key or console password you set at
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

**Implemented and tested** (unit tests, the namespace-lab gates in CI, and
a QEMU boot test of every release with VMware's device models; it also runs
on Steve's own ESXi lab):

- Commit, rollback and commit-confirmed; zones and rules compiled to
  nftables; masquerade NAT; a policy change re-evaluates existing
  connections.
- Host tags through a REST API (and XML user-ID messages for existing
  integrations), applied in about 20 ms, no commit needed.
- App Identification (nDPI) with application, category and group rules.
- IPS (Suricata, Emerging Threats Open) on chosen allow rules, with
  per-rule profiles and a threat log.
- Static routes, VRFs and VLAN subinterfaces, BGP and OSPF (FRR); a DHCP
  server (Kea).
- A web UI and a captive configure-and-commit CLI; traffic, threat and
  system logs with queries; dashboard statistics.
- Signed in-place upgrades with automatic restore and rollback.

**Not implemented** (from the original plan, and not claimed): high
availability, a packet-capture test suite, performance testing or tuning,
external log storage, IPv6, TLS decryption. Nothing has been independently
security-tested.

The original build plan, for reference:

| Phase | Weeks | Gate | State |
| --- | --- | --- | --- |
| 0 · Lab, skeleton | 1–2 | One command builds and tests the lab | done |
| 1 · Stateful core | 3–6 | Tag API blocks a host in under 1 s; rollback restores | done |
| 2 · Features | 7–11 | PCAP suite passes: apps denied by name, test signatures drop | features built; the PCAP suite isn't |
| 3 · Polish and HA | 12–16 | Failover keeps sessions; 1 Gbps with IPS on | web UI and upgrades only; no HA, no performance work |

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

SJB-OS's own code (Go, one small C program, shell and a plain JavaScript web
UI) configures and connects these projects, which do the real work:

- **Linux** netfilter: nftables (the firewall), conntrack (connection
  tracking), NFQUEUE (handing packets to inspection)
- **[nDPI](https://github.com/ntop/nDPI)** (ntop): application identification
- **[Suricata](https://suricata.io)** (OISF) with the
  **[Emerging Threats Open](https://rules.emergingthreats.net/)** signatures
  (Proofpoint): intrusion prevention
- **[FRRouting](https://frrouting.org)**: BGP and OSPF
- **[ISC Kea](https://www.isc.org/kea/)**: DHCP
- **[Debian](https://www.debian.org)** 13, OpenSSH, OpenSSL, open-vm-tools
- **[Go](https://go.dev)** and gopkg.in/yaml.v3

Licenses and source locations: [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing and security

Issues are welcome, especially bugs and ideas. As a demonstration with one
maintainer, pull requests may not be merged. To report a security problem,
see [SECURITY.md](SECURITY.md); please don't open a public issue for it.

## License

Apache License 2.0: see [LICENSE](LICENSE) and [NOTICE](NOTICE). The
appliance image and upgrade bundles also contain third-party software under
its own licenses, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

SJB-OS is an experimental demonstration, not a supported product, and comes
with no warranty (see the license). SJB-OS is not affiliated with or endorsed
by any security vendor.
