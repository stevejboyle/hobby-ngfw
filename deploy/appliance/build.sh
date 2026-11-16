#!/usr/bin/env bash
# Build the SJB-OS VMware appliance (OVA): Stops Junk at the Border.
#
# Needs Go and Docker (with linux/amd64 support; on Apple Silicon, OrbStack or
# Docker Desktop with Rosetta). Output: build/appliance/sjb-os-<version>.ova
# and, when the release signing key is present, sjb-os-<version>.upgrade
# (the signed bundle that upgrades a running appliance in place).
#
# Usage: deploy/appliance/build.sh            (VERSION defaults to git describe)
#   SIGNING_KEY=path   upgrade signing key (default ~/.config/sjb-os/upgrade-signing.key)
#   MIN_FROM=x.y.z     oldest installed version the bundle may upgrade (default
#                      0.8.0)
#   BUNDLE_ONLY=1      build only the .upgrade bundle, not the OVA (fast; test it
#                      with boot-test.sh LAST.raw NEW.upgrade)
#   NO_BUNDLE=1        build the OVA without a bundle when there's no signing
#                      key (otherwise a missing key stops the build)
#   BASE_RAW=path      image the bundle's Debian packages are worked out against
#                      (default build/appliance/sjb-os-0.9.9-r03.raw)
#   PACKAGES="..."     Debian packages bundles carry (default: frr frr-pythontools kea-dhcp4-server libnetfilter-queue1 suricata)
#   ROOT_KEY_FILE=path SSH public key the OVA lets root log in with (your own lab
#                      builds only; never for a published release: release images
#                      carry no root key, operators set one at deploy time)
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}
OUT=build/appliance
mkdir -p "$OUT/bin" build/cache

# A release needs its bundle: without the signing key, stop now rather than
# after the slow image build.
SIGNING_KEY=${SIGNING_KEY:-$HOME/.config/sjb-os/upgrade-signing.key}
if [[ ! -f $SIGNING_KEY && ${NO_BUNDLE:-} != 1 ]]; then
	echo "no signing key at $SIGNING_KEY: can't build the .upgrade bundle"
	echo "(set SIGNING_KEY, or NO_BUNDLE=1 to build just the OVA)"
	exit 1
fi

echo "==> building amd64 binaries ($VERSION)"
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/bin/" ./cmd/...

# App Identification: appidd (C) and the nDPI it uses, built in a Debian 13 container.
# Rebuilt only when its sources change (nDPI takes a few minutes).
stamp=$(cat appidd/appidd.c deploy/appliance/build-appidd.sh | shasum -a 256 | cut -c1-16)
if [[ $(cat "$OUT/appidd/.stamp" 2>/dev/null) != "$stamp" ]]; then
	echo "==> building appidd and nDPI"
	rm -rf "$OUT/appidd"
	docker run --rm --platform linux/amd64 -v "$PWD":/src -w /src debian:trixie \
		bash deploy/appliance/build-appidd.sh /src "/src/$OUT/appidd" /src/build/cache
	echo "$stamp" >"$OUT/appidd/.stamp"
fi
# The compiler, validation and UI use the catalog embedded in ngfwd; it must
# be the one this nDPI build generates, or rules would match the wrong IDs.
if ! cmp -s "$OUT/appidd/catalog.json" internal/appid/catalog.json; then
	echo "nDPI's application catalog differs from internal/appid/catalog.json:"
	echo "  cp $OUT/appidd/catalog.json internal/appid/catalog.json, review, and rebuild"
	exit 1
fi

if [[ ${BUNDLE_ONLY:-} == 1 ]]; then
	echo "==> BUNDLE_ONLY: skipping the OVA"
else
	echo "==> building image in a linux/amd64 container"
	rm -f "$OUT/dev-root-key.pub"
	if [[ -n ${ROOT_KEY_FILE:-} ]]; then
		grep -q '^ssh-' "$ROOT_KEY_FILE" || { echo "ROOT_KEY_FILE $ROOT_KEY_FILE holds no SSH public key"; exit 1; }
		cp "$ROOT_KEY_FILE" "$OUT/dev-root-key.pub"
		echo "WARNING: development image: root may log in with $(awk '{print $NF}' "$ROOT_KEY_FILE" | head -1). Never publish it."
	fi
	# Corresponding-source manifest: build-image.sh adds the image's Debian
	# packages and ships it as /usr/share/sjb-os/licenses/SOURCES-image.txt.
	deploy/appliance/sources-manifest.sh "$VERSION" "$OUT/sources-base.txt"
	docker run --rm --privileged --platform linux/amd64 \
		-v "$PWD":/src -w /src -e VERSION="$VERSION" \
		debian:trixie bash deploy/appliance/build-image.sh
	rm -f "$OUT/dev-root-key.pub"
fi

echo "==> upgrade bundle"
MIN_FROM=${MIN_FROM:-0.8.0}
if [[ -f $SIGNING_KEY ]]; then
	# The bundle carries what the image build installs from this repo: the
	# binaries, the rootfs overlay and the version file. Nothing else.
	STAGE=$OUT/stage
	rm -rf "$STAGE"
	mkdir -p "$STAGE/usr/local/sbin" "$STAGE/etc"
	cp -R deploy/appliance/rootfs/. "$STAGE/"
	find "$STAGE" -name .DS_Store -delete
	install -m 755 "$OUT/bin/ngfwd" "$OUT/bin/fwctl" "$OUT/bin/tlsd" "$OUT/appidd/appidd" "$STAGE/usr/local/sbin/"
	install -d "$STAGE/usr/share/sjb-os/lib" "$STAGE/usr/share/sjb-os/appid" "$STAGE/usr/share/sjb-os/licenses"
	install -m 644 "$OUT"/appidd/libndpi.so.* "$STAGE/usr/share/sjb-os/lib/"
	install -m 644 "$OUT/appidd/catalog.json" "$STAGE/usr/share/sjb-os/appid/"
	install -m 644 "$OUT/appidd/nDPI-COPYING" "$STAGE/usr/share/sjb-os/licenses/"
	install -m 644 LICENSE NOTICE THIRD_PARTY_NOTICES.md "$STAGE/usr/share/sjb-os/licenses/"
	chmod 755 "$STAGE"/usr/local/sbin/* "$STAGE/etc/update-motd.d/10-sjb"
	echo "$VERSION" >"$STAGE/etc/ngfw-version"
	# Debian packages the base image lacks (FRR, Kea and their dependencies), as
	# signed bundle files; sjb-packages installs them on the appliance.
	BASE_RAW=${BASE_RAW:-build/appliance/sjb-os-0.9.9-r03.raw}
	PACKAGES=${PACKAGES:-frr frr-pythontools kea-dhcp4-server libnetfilter-queue1 suricata ca-certificates}
	[[ -f $BASE_RAW ]] || { echo "need the base image $BASE_RAW to work out which packages to bundle"; exit 1; }
	mkdir -p "$STAGE/usr/share/sjb-os/packages"
	docker run --rm --privileged --platform linux/amd64 -v "$PWD":/src -w /src \
		-e BASE_RAW="$BASE_RAW" -e PACKAGES="$PACKAGES" -e DEST="$STAGE/usr/share/sjb-os/packages" \
		debian:trixie bash deploy/appliance/fetch-packages.sh
	# What third-party code this bundle carries and where its source is
	# (fetch-sources.py downloads it); also published beside the bundle.
	deploy/appliance/sources-manifest.sh "$VERSION" "$STAGE/usr/share/sjb-os/licenses/SOURCES.txt" "$STAGE/usr/share/sjb-os/packages"
	cp "$STAGE/usr/share/sjb-os/licenses/SOURCES.txt" "$OUT/sjb-os-$VERSION.sources.txt"
	go run ./cmd/sjbpkg build -root "$STAGE" -version "$VERSION" -min-from "$MIN_FROM" \
		-key "$SIGNING_KEY" -o "$OUT/sjb-os-$VERSION.upgrade"
	go run ./cmd/sjbpkg verify -keys deploy/appliance/rootfs/usr/share/sjb-os/upgrade-keys \
		"$OUT/sjb-os-$VERSION.upgrade" >/dev/null
	rm -rf "$STAGE"
else
	echo "NO_BUNDLE=1: no signing key, so no .upgrade bundle"
	[[ ${BUNDLE_ONLY:-} != 1 ]] || exit 1
fi

ls -lh "$OUT"/*.ova "$OUT"/*.upgrade 2>/dev/null
