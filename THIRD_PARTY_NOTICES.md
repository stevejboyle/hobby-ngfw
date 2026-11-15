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
packages for what older images lack (FRR, Kea, Suricata,
libnetfilter-queue1 and their dependencies) under
`/usr/share/sjb-os/packages`. The main ones:

| Package | Purpose | License |
|---|---|---|
| suricata | IPS engine | GPL-2.0-only |
| frr, frr-pythontools | BGP and OSPF | GPL-2.0-or-later |
| kea-dhcp4-server | DHCP server | MPL-2.0 |
| nftables, conntrack | Packet filtering, connection tracking | GPL-2.0 |
| libnetfilter-queue1, libnetfilter-conntrack3, libnfnetlink0 | appidd's kernel interfaces | GPL-2.0-or-later |
| libmnl0 | netlink library | LGPL-2.1-or-later |
| openssh-server | SSH | BSD-style |
| openssl | TLS | Apache-2.0 |
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

## Open questions

These are not resolved and nothing here is legal advice:

- For the GPL components (the kernel, Suricata, FRR, nftables, the
  netfilter libraries and others), the manifests and fetch script point to
  exact sources held by third parties (snapshot.debian.org, GitHub). Whether
  that satisfies each license's source-offer terms for downloads
  distributed by this project, or whether the source archive should be
  published beside each release (or a written offer included), has not
  been reviewed by counsel.
- `appidd`'s distributed binary combines Apache-2.0 code with
  GPL-2.0-or-later libraries; the combination is treated here as GPL-3.0
  for distribution. This has not been reviewed by counsel.
- The Emerging Threats Open ruleset's terms apply to its use on the
  appliance; they have not been reviewed beyond what is noted below.

## Downloaded at run time, not distributed

When a rule uses an IPS profile, the appliance downloads the **Emerging
Threats Open** ruleset (Proofpoint) from rules.emergingthreats.net. It is
not part of the image or the bundles; it is used under the ruleset's own
terms, in the `LICENSE` file of the downloaded archive.
