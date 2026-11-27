#!/usr/bin/env bash
# Runs in a linux/amd64 Debian container (see build.sh). Resolves against the
# base image's ($BASE_RAW) own dpkg database and downloads into $DEST:
#   - $PACKAGES and whatever they depend on that the base image lacks;
#   - every package installed in the base image that Debian has a newer
#     version of (security fixes, point releases, a new kernel).
# Also writes $DEST/os-updates.txt, one line per updated package:
#   NAME BASE_VERSION NEW_VERSION SUITE security|update
# (BASE_VERSION is "absent" for a package the base image doesn't have).
set -euo pipefail
# The suites, explicitly: the release, its point-release updates and the
# security archive.
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
cat >/etc/apt/sources.list.d/debian.sources <<'S'
Types: deb
URIs: http://deb.debian.org/debian
Suites: trixie trixie-updates
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://deb.debian.org/debian-security
Suites: trixie-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
S
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y -qq fdisk >/dev/null
START=$(sfdisk -d "$BASE_RAW" | awk '/raw1 :/ {gsub(/,/, "", $4); print $4}')
MNT=$(mktemp -d)
mount -o ro,loop,offset=$((START * 512)) "$BASE_RAW" "$MNT"
STATE=$(mktemp -d)
mkdir -p "$STATE/archives/partial"
cp "$MNT/var/lib/dpkg/status" "$STATE/status"
umount "$MNT"
APT=(apt-get -o Dir::State::status="$STATE/status" -o Dir::Cache::archives="$STATE/archives")
"${APT[@]}" install --download-only -y -qq --no-install-recommends $PACKAGES >/dev/null
# OS updates: what a dist-upgrade of the base image would install.
"${APT[@]}" -s -qq dist-upgrade 2>/dev/null | awk '
/^Inst / {
	name = $2; old = "absent"; i = 3
	if ($3 ~ /^\[/) { old = substr($3, 2, length($3) - 2); i = 4 }
	new = substr($i, 2); suite = $(i + 1)
	kind = (suite ~ /[Ss]ecurity/) ? "security" : "update"
	print name, old, new, suite, kind
}' >"$STATE/os-updates.txt"
"${APT[@]}" dist-upgrade --download-only -y -qq --no-install-recommends >/dev/null
if ! compgen -G "$STATE/archives/*.deb" >/dev/null; then
	echo "bundling no packages: the base image already has them all and is up to date"
	exit 0
fi
cp "$STATE"/archives/*.deb "$DEST/"
cp "$STATE/os-updates.txt" "$DEST/os-updates.txt"
echo "bundling $(ls "$DEST"/*.deb | wc -l) package(s), $(du -sh "$DEST" | cut -f1): $(ls "$DEST"/*.deb | xargs -n1 basename | sed 's/_.*//' | xargs)"
echo "OS updates: $(wc -l <"$DEST/os-updates.txt") package(s), $(grep -c ' security$' "$DEST/os-updates.txt" || true) from security"
