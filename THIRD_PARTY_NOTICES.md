# Third-party software

SJB-OS's own code is under the Apache License 2.0 ([LICENSE](LICENSE)). The
appliance image (OVA) and the upgrade bundles also carry the third-party
software below, each under its own license. Nothing here changes those
licenses.

## Built from source by this repository

| Component | Version | License | Source |
|---|---|---|---|
| nDPI (ntop) | 6.0 | LGPL-3.0-or-later | <https://github.com/ntop/nDPI/archive/refs/tags/6.0.tar.gz>, checked by SHA-256 and built unmodified by [`deploy/appliance/build-appidd.sh`](deploy/appliance/build-appidd.sh) |
| gopkg.in/yaml.v3 | 3.0.1 | MIT and Apache-2.0 | <https://github.com/go-yaml/yaml/tree/v3.0.1> |
| Go standard library and runtime | see `go.mod` | BSD-3-Clause | <https://go.dev/LICENSE> |

`appidd` (SJB-OS code, Apache-2.0) is linked against libnetfilter_queue and
libnetfilter_conntrack (GPL-2.0-or-later) and libmnl (LGPL-2.1-or-later).
The `appidd` binary as distributed is therefore also subject to the GNU GPL;
its complete source is this repository, and the libraries' sources are
Debian's (below).

## Debian packages

The image is Debian 13 ("trixie"). Upgrade bundles carry Debian's own
packages for what older images lack (FRR, Kea, Suricata,
libnetfilter-queue1 and their dependencies) under
`/usr/share/sjb-os/packages`. The main ones:

| Package | Purpose | License |
|---|---|---|
| suricata | IPS engine | GPL-2.0-only |
| frr, frr-pythontools | BGP and OSPF | GPL-2.0-or-later |
| kea-dhcp4-server | DHCP server | MPL-2.0 |
| nftables, conntrack | Packet filtering, connection tracking | GPL-2.0 |
| libnetfilter-queue1, libnetfilter-conntrack3 | appidd's kernel interfaces | GPL-2.0-or-later |
| libmnl0 | netlink library | LGPL-2.1-or-later |
| openssh-server | SSH | BSD-style |
| openssl | TLS | Apache-2.0 |
| open-vm-tools | VMware guest tools | LGPL-2.1 and GPL-2.0 |
| linux-image-amd64 | Kernel | GPL-2.0 |

Every Debian package's exact license is in `/usr/share/doc/<package>/copyright`
on the appliance. Their source code is at <https://sources.debian.org/> and,
for the exact versions in a given image, <https://snapshot.debian.org/>.

## Downloaded at run time, not distributed

When a rule uses an IPS profile, the appliance downloads the **Emerging
Threats Open** ruleset (Proofpoint) from rules.emergingthreats.net. It is
not part of the image or the bundles; it is used under the ruleset's own
terms, in the `LICENSE` file of the downloaded archive.
