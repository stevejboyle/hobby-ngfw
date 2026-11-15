#!/usr/bin/env python3
"""Download the corresponding source of an SJB-OS build.

  fetch-sources.py MANIFEST OUTDIR [--only NAME ...]

MANIFEST is the SOURCES.txt an SJB-OS bundle or image ships in
/usr/share/sjb-os/licenses (also published beside each release), written by
sources-manifest.sh. Every record it lists is fetched into OUTDIR:

  ndpi       the release tarball, checked against its SHA-256
  gomod      the module zip from the Go module proxy
  deb        the Debian source package (.dsc and its files) at that exact
             version, from snapshot.debian.org
  debbin     the same, after looking up which source package built it
  sjb-os     a note: the source is the repository at that commit

Standard library only. Re-running skips files already downloaded.
"""
import hashlib
import json
import os
import sys
import urllib.request

SNAPSHOT = "https://snapshot.debian.org"
GOPROXY = "https://proxy.golang.org"


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sjb-os-fetch-sources"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()


def save(path, url, sha256=None):
    if os.path.exists(path):
        return
    data = get(url)
    if sha256 and hashlib.sha256(data).hexdigest() != sha256:
        raise SystemExit(f"{url}: SHA-256 mismatch")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".part", "wb") as f:
        f.write(data)
    os.replace(path + ".part", path)


def debian_source(out, src, ver):
    """Fetch every file of source package src at version ver."""
    info = json.loads(get(f"{SNAPSHOT}/mr/package/{src}/{ver}/srcfiles?fileinfo=1"))
    d = os.path.join(out, "debian", f"{src}_{ver}")
    for entry in info["result"]:
        h = entry["hash"]
        name = info["fileinfo"][h][0]["name"]
        save(os.path.join(d, name), f"{SNAPSHOT}/file/{h}")
    return d


def debian_binary_source(pkg, ver):
    """Which source package (and version) built binary pkg at version ver."""
    info = json.loads(get(f"{SNAPSHOT}/mr/binary/{pkg}/"))
    for r in info["result"]:
        if r["binary_version"] == ver:
            return r["source"], r["version"]
    raise SystemExit(f"snapshot.debian.org doesn't know {pkg} {ver}")


def main(argv):
    if len(argv) < 3:
        raise SystemExit(__doc__)
    manifest, out = argv[1], argv[2]
    only = set(argv[argv.index("--only") + 1:]) if "--only" in argv else None
    os.makedirs(out, exist_ok=True)
    done = set()
    for line in open(manifest):
        f = line.split()
        if not f or f[0].startswith("#"):
            continue
        kind = f[0]
        name = f[1] if len(f) > 1 else ""
        if only and name not in only and kind not in only:
            continue
        if kind == "ndpi":
            ver, url, sha = f[1], f[2], f[3].removeprefix("sha256:")
            save(os.path.join(out, "ndpi", f"nDPI-{ver}.tar.gz"), url, sha)
        elif kind == "gomod":
            mod, ver = f[1], f[2]
            save(os.path.join(out, "go", mod.replace("/", "_") + f"@{ver}.zip"), f"{GOPROXY}/{mod}/@v/{ver}.zip")
        elif kind in ("deb", "debbin"):
            src, sver = (f[3], f[4]) if kind == "deb" else debian_binary_source(f[1], f[2])
            if (src, sver) not in done:
                done.add((src, sver))
                debian_source(out, src, sver)
        elif kind == "sjb-os":
            with open(os.path.join(out, "SJB-OS-SOURCE.txt"), "w") as n:
                n.write(f"SJB-OS {f[1]}: {f[3]} at commit {f[2]}\n")
        else:
            continue
        print(f"ok  {kind} {' '.join(f[1:3])}")
    print(f"sources in {out}")


if __name__ == "__main__":
    main(sys.argv)
