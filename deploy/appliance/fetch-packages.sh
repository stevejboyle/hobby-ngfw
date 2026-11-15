#!/usr/bin/env bash
# Runs in a linux/amd64 Debian container (see build.sh). Downloads $PACKAGES
# and whatever they depend on that the base image ($BASE_RAW) doesn't already
# have, into $DEST, by resolving against the image's own dpkg database.
set -euo pipefail
apt-get update -qq >/dev/null
apt-get install -y -qq fdisk >/dev/null
START=$(sfdisk -d "$BASE_RAW" | awk '/raw1 :/ {gsub(/,/, "", $4); print $4}')
MNT=$(mktemp -d)
mount -o ro,loop,offset=$((START * 512)) "$BASE_RAW" "$MNT"
STATE=$(mktemp -d)
mkdir -p "$STATE/archives/partial"
cp "$MNT/var/lib/dpkg/status" "$STATE/status"
umount "$MNT"
apt-get -o Dir::State::status="$STATE/status" -o Dir::Cache::archives="$STATE/archives" \
	install --download-only -y -qq --no-install-recommends $PACKAGES >/dev/null
if ! compgen -G "$STATE/archives/*.deb" >/dev/null; then
	echo "bundling no packages: the base image already has them all"
	exit 0
fi
cp "$STATE"/archives/*.deb "$DEST/"
echo "bundling $(ls "$DEST" | wc -l) package(s), $(du -sh "$DEST" | cut -f1): $(ls "$DEST" | sed 's/_.*//' | xargs)"
