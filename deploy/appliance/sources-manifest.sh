#!/usr/bin/env bash
# Write the corresponding-source manifest of an SJB-OS build: exactly what
# third-party code the bundle or image carries and where its source is.
# One record per line, space-separated, so fetch-sources.py can download
# everything it lists:
#
#   sjb-os VERSION COMMIT REPO_URL
#   ndpi VERSION TARBALL_URL sha256:HASH
#   go VERSION
#   gomod MODULE VERSION
#   debbin PACKAGE VERSION           Debian binary package shipped in a bundle
#   deb PACKAGE VERSION SOURCE SOURCE_VERSION   (added by build-image.sh for the OVA)
#
# Usage: sources-manifest.sh VERSION OUT [DEB_DIR]
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=$1 OUT=$2 DEBS=${3:-}
eval "$(grep -E '^NDPI_(VERSION|SHA256)=' deploy/appliance/build-appidd.sh)"
commit=$(git rev-parse HEAD)
git diff --quiet HEAD -- . ':!build' 2>/dev/null || commit="$commit+local-changes"
{
	echo "# SJB-OS $VERSION: corresponding source for the third-party code it ships."
	echo "# deploy/appliance/fetch-sources.py downloads everything listed here."
	echo "sjb-os $VERSION $commit https://github.com/stevejboyle/hobby-ngfw"
	echo "ndpi $NDPI_VERSION https://github.com/ntop/nDPI/archive/refs/tags/$NDPI_VERSION.tar.gz sha256:$NDPI_SHA256"
	echo "go $(go env GOVERSION)"
	# Modules compiled into the shipped binaries (not test-only ones).
	GOOS=linux GOARCH=amd64 go list -deps -f '{{with .Module}}{{if not .Main}}gomod {{.Path}} {{.Version}}{{end}}{{end}}' ./cmd/ngfwd ./cmd/fwctl | sort -u
	if [[ -n $DEBS && -d $DEBS ]]; then
		for f in "$DEBS"/*.deb; do
			[[ -e $f ]] || continue
			b=$(basename "$f" .deb)        # name_version_arch, ':' as %3a
			name=${b%%_*} rest=${b#*_}
			ver=${rest%_*}
			echo "debbin $name ${ver//%3a/:}"
		done
	fi
} >"$OUT"
