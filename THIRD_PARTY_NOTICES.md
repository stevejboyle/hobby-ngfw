# Third-party software

SJB-OS's own code is under the Apache License 2.0 ([LICENSE](LICENSE)). The
appliance image (OVA) and the upgrade bundles also carry the third-party
software below, each under its own license. Nothing here changes those
licenses.

## Built from source by this repository

| Component | Version | License | Source |
|---|---|---|---|
| nDPI (ntop) | 6.0 | LGPL-3.0-or-later (its tarball also bundles third-party code under its own licenses, in `src/lib/third_party`) | <https://github.com/ntop/nDPI/archive/refs/tags/6.0.tar.gz>, checked by SHA-256 and built unmodified (`./configure --with-only-libndpi`) by [`deploy/appliance/build-appidd.sh`](deploy/appliance/build-appidd.sh); its license ships as `nDPI-COPYING` |
| gopkg.in/yaml.v3 | 3.0.1 | MIT and Apache-2.0 | <https://github.com/go-yaml/yaml/tree/v3.0.1> |
| Go standard library and runtime | see `go.mod` | BSD-3-Clause | <https://go.dev/LICENSE> |

`appidd` (SJB-OS code, Apache-2.0) is linked against libnetfilter_queue,
libnetfilter_conntrack and libnfnetlink (GPL-2.0-or-later) and libmnl
(LGPL-2.1-or-later).
The `appidd` binary as distributed is therefore also subject to the GNU GPL;
its complete source is this repository, and the libraries' sources are
Debian's (below).

## Debian packages

The image is Debian 13 ("trixie"). Upgrade bundles carry Debian's own
packages for what older images lack (FRR, Kea, Suricata, net-snmp's snmpd,
libnetfilter-queue1, ca-certificates and their dependencies) under
`/usr/share/sjb-os/packages`. The main ones:

| Package | Purpose | License |
|---|---|---|
| suricata | IPS engine | GPL-2.0-only |
| frr, frr-pythontools | BGP and OSPF | GPL-2.0-or-later |
| kea-dhcp4-server | DHCP server | MPL-2.0 |
| snmpd (net-snmp) | SNMP agent | BSD-style (net-snmp's COPYING, several BSD licenses) |
| nftables, conntrack | Packet filtering, connection tracking | GPL-2.0 |
| libnetfilter-queue1, libnetfilter-conntrack3, libnfnetlink0 | appidd's kernel interfaces | GPL-2.0-or-later |
| libmnl0 | netlink library | LGPL-2.1-or-later |
| openssh-server | SSH | BSD-style |
| openssl | TLS | Apache-2.0 |
| ca-certificates | Trusted root certificates (TLS decryption checks servers against them) | MPL-2.0 (the Mozilla CA list), GPL-2.0-or-later (scripts) |
| open-vm-tools | VMware guest tools | LGPL-2.1 and GPL-2.0 |
| linux-image-amd64 | Kernel | GPL-2.0 |

Every Debian package's exact license is in `/usr/share/doc/<package>/copyright`
on the appliance.

## Corresponding source

Each build writes a manifest of exactly what third-party code it ships and
where its source is, one record per line:

- `/usr/share/sjb-os/licenses/SOURCES.txt` in every upgrade bundle (and
  `sjb-os-<version>.sources.txt` beside it): SJB-OS's own commit, nDPI's
  version, URL and SHA-256, the Go toolchain and modules compiled in, and
  any Debian binary packages the bundle carries;
- `/usr/share/sjb-os/licenses/SOURCES-image.txt` in the OVA (and
  `sjb-os-<version>.ova-sources.txt` beside it): the same plus every Debian
  package installed in the image, with its source package and exact
  version.

[`deploy/appliance/fetch-sources.py`](deploy/appliance/fetch-sources.py)
downloads everything a manifest lists: Debian source packages at those exact
versions from snapshot.debian.org, the checksum-verified nDPI tarball, and
the Go modules. The build scripts in this repository (`deploy/appliance/`)
are the scripts used to build the images and bundles.

## How these licenses are met

SJB-OS follows the standard terms of each license:

- **GPL and LGPL components** (the Linux kernel, Suricata, FRR, nftables,
  the netfilter libraries, nDPI and the other Debian packages): every
  release publishes the corresponding-source manifests beside its
  downloads, and a release that ships third-party code built by this
  repository also attaches that source (`sjb-os-<version>-sources.tar.gz`:
  nDPI's tarball, the Go modules and SJB-OS's own source). Debian packages
  are unmodified Debian builds; their exact sources are listed in the
  manifests and fetched by `fetch-sources.py`. In addition, the written
  offer below covers everything.
- **nDPI (LGPL-3.0-or-later)** ships unmodified as a separate shared
  library (`/usr/share/sjb-os/lib/libndpi.so.6`) that `appidd` links
  dynamically, so it can be replaced; its license is in
  `/usr/share/sjb-os/licenses/nDPI-COPYING`.
- **appidd**: its own source is Apache-2.0; the binary as distributed links
  GPL-2.0-or-later libraries, so it is distributed under the GNU GPL
  version 3 (with which Apache-2.0 is compatible). Its complete source is
  this repository at the commit each manifest records.
- **MPL-2.0 (Kea), BSD, MIT and Apache-2.0 components** keep their notices
  in `/usr/share/doc/<package>/copyright` on the appliance and in the
  source they come from.
- **Emerging Threats Open** signatures are not redistributed: each
  appliance downloads them from Proofpoint and uses them under the
  ruleset's own terms.

### Written offer for source code

For at least three years after SJB-OS's last distribution of a given
version, anyone may obtain the complete corresponding source code, in
machine-readable form, of every GPL- or LGPL-licensed component that
version's OVA or upgrade bundle contains, for no more than the cost of
providing it. Ask by opening an issue at
<https://github.com/stevejboyle/sjb-os/issues> naming the version.

## Data

- **DB-IP IP to Country Lite** (https://db-ip.com), licensed under the
  Creative Commons Attribution 4.0 International License (CC BY 4.0):
  IP Geolocation by DB-IP. A converted copy (IPv4 ranges by country,
  `/usr/share/sjb-os/geoip`) ships in the image and in upgrade bundles, and
  the appliance downloads newer months from DB-IP. The attribution is shown
  wherever the data is (`show geoip`, the web UI's Geo-blocking panel).

## Downloaded at run time, not distributed

When a rule uses an IPS profile, the appliance downloads the **Emerging
Threats Open** ruleset (Proofpoint) from rules.emergingthreats.net. It is
not part of the image or the bundles; it is used under the ruleset's own
terms, in the `LICENSE` file of the downloaded archive.
