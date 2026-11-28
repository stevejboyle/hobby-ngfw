# Release description template

Start every GitHub release's notes from this. Keep the first paragraph and
the attribution as they are; fill in the rest. Describe what was built and
tested, never what it is equivalent to, and don't compare it to commercial
products.

## Publishing (after `gh release create`)

Online updates read the release index on the update server. With Steve's
go-ahead, sign a new index for the release and push it to the Pages repo
that serves `updates.os.sjbconsulting.ai`:

```bash
go run ./cmd/sjbpkg index -bundle build/appliance/sjb-os-<version>.upgrade \
  -url https://github.com/stevejboyle/sjb-os/releases/download/v<version>/sjb-os-<version>.upgrade \
  -notes https://github.com/stevejboyle/sjb-os/releases/tag/v<version> \
  -key ~/.config/sjb-os/upgrade-signing.key -o ../sjb-os-updates
```

Then commit and push `v1/stable.json` and `v1/stable.json.sig` in
`../sjb-os-updates`. Appliances on 0.9.17 or later find the release within a
day.

---

**An experimental demonstration of AI-generated software for isolated lab
use. Not a commercial, supported, or production-ready security product. Do
not rely on it to protect production systems. Working code does not
establish security effectiveness, resilience, or operational readiness.**

## Download

- `sjb-os-<version>.ova`: new installs (vSphere 8.0 U1 or later). *(Only
  when the release has a new image.)*
- `sjb-os-<version>.upgrade`: upgrades appliances on <minimum version> or
  later in place (Web UI → System → Administration → Upgrade).
- `*.sha256`: check each download against its checksum.
- `sjb-os-<version>.sources.txt` (and `.ova-sources.txt` with an image): the
  exact third-party code shipped and where its source is;
  `deploy/appliance/fetch-sources.py` downloads it. See
  THIRD_PARTY_NOTICES.md.

## What changed

<What is new or fixed, in terms of what an operator sees. Note anything
that interrupts existing connections or changes CLI syntax.>

## Verification

<What was actually run: unit tests, the lab gates, the boot test (which
image, which bundle, how many checks), anything tested on real hardware.
Say what was not run.>

## Credits

Steve Boyle used Claude Code to generate the project-specific
implementation, tests, and documentation under his direction. He also used
ChatGPT to review the code and help optimize and finalize the solution,
including identifying correctness gaps and defining release-readiness fixes.
SJB-OS builds on Linux netfilter (nftables, conntrack), nDPI, Suricata with
the Emerging Threats Open signatures, FRRouting, ISC Kea, OpenSSH and
Debian; their licenses are in THIRD_PARTY_NOTICES.md.
