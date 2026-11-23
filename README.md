# SJB-OS: an experiment in building systems software with AI

**The goal of this project is to find out how far one person can get
building a real, complex piece of systems software (here, a firewall
appliance) by directing an AI coding assistant instead of writing code, and
to record the evidence honestly: what got built, how it was tested, and how
much human time it took.** It is not an attempt to build a firewall anyone
should rely on.

> **An experimental demonstration of AI-generated software for isolated lab
> use. Not a commercial, supported, or production-ready security product. Do
> not rely on it to protect production systems. Working code does not
> establish security effectiveness, resilience, or operational readiness.**

**The short version:** [the product brief](docs/SJB-OS-product-brief.pdf)
(two-page PDF): what got built, and how building it with AI compares with
building it the usual way. **The long version:** [the administrator
guide](docs/SJB-OS-administrator-guide.pdf) (PDF): deploying, configuring
and running it.

## How it was built

Steve Boyle used Claude Code to generate the project-specific implementation,
tests, and documentation under his direction. He also used ChatGPT to review
the code and help optimize and finalize the solution, including identifying
correctness gaps and defining release-readiness fixes. Steve supplied the
architecture, requirements and decisions, and tested the results on his own
lab appliances.

> I intentionally did not write, or even look at, a single line of code
> during this whole process. That isn't a good idea, and it isn't how a real
> software design process should ever work. It's simply an example of where
> we are today.
>
> Steve Boyle, SJB Consulting

That statement is about Steve's own work: the code was still reviewed, by
AI (ChatGPT) and by the automated tests and boot tests described below.

## The evidence

- **Time:** the first milestone took nine days of calendar time
  (2026-11-08 to 2026-11-16, 38 releases through 0.9.9-r08) and about
  27.3 hours of Steve's active time. Of that, 22.9 hours took it to its
  first full release (0.9.9-r03), and TLS decryption (0.9.9-r04 to r06)
  took 0.6 hours. Later work (multiple users, inbound NAT, trunks, the
  DMZ lab, review follow-ups, log forwarding and backups, and the
  management certificate, hairpin NAT and IPS exceptions, through
  2026-11-23 and 0.9.12-r01) brings the total to 31.6 hours. The hours are estimates of active time derived from the session
  transcripts, not stopwatch measurements: a gap between Steve's messages
  counts in full up to 30 minutes and as 5 minutes beyond that, and one
  0.5-hour figure (his ChatGPT review) is his own estimate. Row by row:
  [docs/effort-log.md](docs/effort-log.md).
- **AI cost:** a $20/month Claude Pro plan. The 1.60 billion tokens it
  used through 2026-11-17 (nearly all cached context, counted from the
  session transcripts) would cost about $510 at Claude API list prices.
  ChatGPT's review isn't included.
- **Size:** on 2026-11-17, about 28,500 lines of Go, C, JavaScript, shell
  and Python, not counting comments and blank lines: 21,500 product, 7,000
  tests.
- **Testing:** unit tests, network-namespace gates in CI (including
  established sessions across policy changes), and a QEMU boot test with
  VMware's device models: about 150 end-to-end checks of first boot,
  policy, application identification, intrusion prevention, TLS
  decryption, routing, DHCP, upgrades and rollback (every release through
  0.9.9-r08; since then, version bumps, while revisions run the tests that
  cover what changed). From a client VM behind the firewall,
  [`tools/fw-traffic-test.sh`](tools/fw-traffic-test.sh) exercises App
  Identification, the IPS and TLS decryption, and
  [`tools/policy-test.sh`](tools/policy-test.sh) checks the
  [best-practice policy](examples/best-practice.yaml): 47 checks passed,
  none failed, on Steve's appliance on 2026-11-17. That run predates a
  2026-11-21 harness fix: its risky-application checks could count a
  local curl failure, such as an untrusted certificate, as a block. They
  now count only a refused, dropped or reset connection, and
  `make harness-test` checks the harnesses' verdicts offline.
- **Releases:** 38 in the first nine days (through 0.9.9-r08), each gated
  by the boot test; 42 through 2026-11-20 (0.9.10-r02). Since r08,
  version bumps and the r10 fix get the boot test, and other revisions
  run the tests that cover their change. The public history starts at
  0.9.9-r01; the earlier releases are kept privately.
- **Design:** [docs/architecture.md](docs/architecture.md).

### Compared with building it the usual way

| | Built the usual way (estimate) | Built with AI (from the record) |
| --- | --- | --- |
| Time to build | About a year | 9 days, Nov 8 to 16, 2026 (to 0.9.9-r08) |
| People | One specialist, or about six engineers | One person directing AI |
| Human hours | 2,400 to 12,300 engineering hours | About 27.3 hours in those nine days (31.6 through Nov 23), estimated from the session transcripts |
| Cost | $350,000 to $1.1 million in salary and benefits | A $20/month Claude Pro plan ($510 of tokens at API list prices) |

The left column is a model-based estimate; the right comes from the
effort log and the release history:

- **Low end:** a component-by-component estimate for one senior specialist
  who already knows this stack: 49 weeks of work (6 of them for TLS
  decryption) plus 20% for integration and testing, about 59 weeks or
  2,350 hours. Priced at the 90th-percentile US wage for software
  developers ($214,670 a year), about $147 an hour with benefits: about
  $350,000.
- **High end:** the basic COCOMO model (organic mode) applied to the 28,500
  lines (2026-11-17): 81 person-months, about six people for about 13
  months, or 12,300 hours. Priced at the median wage ($64.44 an hour),
  about $92 an hour with benefits: about $1.1 million.
- **Benefits:** wages are about 70% of what employers pay in total (BLS
  Employer Costs for Employee Compensation), so wages are divided by 0.7.
- **Caveats:** COCOMO dates from 1981 and tends to run high for modern
  code; the low end assumes an expert. Most of the hard work is done by
  existing open-source engines (nftables, nDPI, Suricata, FRR, Kea), and
  the line count covers only the new code. Neither estimate prices
  Steve's own design judgment, and the speed says nothing about whether
  the result is secure (see below).

Sources: [BLS Occupational Outlook Handbook, software
developers](https://www.bls.gov/ooh/computer-and-information-technology/software-developers.htm)
(May 2025 wages); [BLS Employer Costs for Employee
Compensation](https://www.bls.gov/news.release/ecec.nr0.htm); Claude API
list prices for the token figure.

What this does *not* show: that the result is secure, robust under real
traffic, fast, or maintainable over years. Everything that makes a security
product trustworthy beyond working code (independent testing, threat
research, performance engineering, support, certification, long-term
maintenance) is out of scope.

## What got built

SJB-OS ("Stops Junk at the Border") is a firewall appliance for VMware:
zone-based policy compiled to nftables, application identification with
nDPI, inline intrusion prevention with Suricata, outbound TLS decryption,
host tagging through an API, routing and DHCP, managed with a commit/rollback configuration model
from a web UI and a CLI. See [Status](#status) for exactly what is
implemented and tested.

The heavy lifting happens in established open-source software that SJB-OS
configures and ties together: the Linux kernel's netfilter (nftables,
conntrack, NFQUEUE), nDPI, Suricata with the Emerging Threats Open
signatures, FRRouting, ISC Kea, OpenSSH and Debian. Their authors deserve
the credit for what they do; see [Built on](#built-on).

## Deploying

If you want to try it in a lab, the OVA is the way to run it. Deploy it on
vSphere 8.0 U1 or later with three networks: **mgmt**, **inside** and **outside**.

1. Download the OVA from [Releases](https://github.com/stevejboyle/sjb-os/releases)
   (or build it, below) and check its `.sha256`.
2. In vSphere, **Deploy OVF Template** and map Network adapter 1 → mgmt,
   2 → inside, 3 → outside.
3. Fill in the deployment settings (vCenter), or set `guestinfo.ngfw.*`
   advanced settings (standalone ESXi), or accept the defaults.
4. Power on. The console shows the SJB-OS mark, the addresses and "SJB-OS ready: standing guard at the border."
5. Open the web UI at `https://<mgmt-ip>/` and log in as `admin` with the
   password from the console, or `ssh admin@<mgmt-ip>` for the CLI.

Operators get a CLI, never a Unix shell: `admin` has no bash and no sudo.
`admin` is the permanent superuser; add a user for each person, with a
built-in role (superuser, admin, read-only) or a custom one, on System →
Users or with `request user add` in the CLI. Root logs in only with the SSH key or console password you set at
deploy time, for recovery; no root key or password ships with SJB-OS.

Later releases install in place: upload the signed `.upgrade` file on the web
UI (System → Administration).

The full guide, with settings, first-boot behaviour and day-to-day use, is
[deploy/appliance/README.md](deploy/appliance/README.md); the same ground,
laid out for reading or printing, is in the
[administrator guide](docs/SJB-OS-administrator-guide.pdf) (PDF).

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
  nftables; source NAT, port forwarding and 1:1 static NAT (0.9.10-r01) for
  publishing servers, with hairpin NAT (0.9.12-r01); a policy change
  re-evaluates existing connections.
- Host tags through a REST API (and XML user-ID messages for existing
  integrations), applied in about 20 ms, no commit needed.
- App Identification (nDPI) with application, category and group rules.
- IPS (Suricata, Emerging Threats Open) on chosen allow rules, with
  per-rule profiles, a threat log, and exceptions for one signature by
  rule, client or server (0.9.12-r01).
- Outbound TLS decryption (0.9.9-r04 to r06) with a CA on the appliance:
  the rules, App Identification and the IPS see inside HTTPS; banking,
  payment, health and government sites excluded; pinned apps passed
  through; fail-open. See the guide's caveats first.
- Static routes, VRFs and VLAN subinterfaces, BGP and OSPF (FRR); a DHCP
  server (Kea).
- A web UI and a captive configure-and-commit CLI; traffic, threat,
  decryption and system logs with queries; dashboard statistics.
- Log forwarding to syslog servers or a SIEM (0.9.11-r01): RFC 5424 over
  TLS, TCP or UDP, JSON or CEF, per-server log types.
- Config backup and restore (0.9.11-r01), optionally with users, roles and
  tag API keys (then always encrypted); restores go through the candidate
  and a normal commit.
- Multiple local users with role-based access: built-in superuser, admin
  and read-only roles, custom roles by area (view or change), config
  changes checked against the areas they touch, per-user SSH keys, account
  lockout, and every change recorded under the user the firewall verified.
  Directory sign-in (LDAP, RADIUS, SAML, OIDC) is not built yet.
- Signed in-place upgrades with automatic restore and rollback.
- An operator's own certificate (e.g. from a lab CA) for the web UI and
  tag API (0.9.12-r01), applied without a restart.

**Not implemented** (from the original plan, and not claimed): high
availability, a packet-capture test suite, performance testing or tuning,
log storage and search beyond the appliance's own journal (logs can be
forwarded to a SIEM, which stores them), IPv6, inbound (server) TLS decryption. Nothing has
been independently security-tested.

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
