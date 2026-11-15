#!/usr/bin/env bash
# Builds appidd and the nDPI library it uses, for the appliance (Debian 13,
# amd64). Runs inside a linux/amd64 debian:trixie container (see build.sh):
#
#   build-appidd.sh SRC_DIR OUT_DIR CACHE_DIR
#
# Debian's nDPI is 4.2 (2021), too old for today's TLS/QUIC apps, so the
# pinned nDPI release below is built from source; the tarball is cached in
# CACHE_DIR and checked against its sha256. Output in OUT_DIR:
#   appidd             -> /usr/local/sbin/appidd
#   libndpi.so.<N>     -> /usr/share/sjb-os/lib/ (named by its SONAME)
#   catalog.json       -> /usr/share/sjb-os/appid/catalog.json
#   nDPI-COPYING       -> /usr/share/sjb-os/licenses/nDPI-COPYING (LGPLv3)
set -euo pipefail
SRC=$1 OUT=$2 CACHE=$3
NDPI_VERSION=6.0
NDPI_SHA256=21fc40cab5505942c0b21d9bbaf73e9adf8162ddfe782e4cd072cab855a2eda9
LIBDIR=/usr/share/sjb-os/lib

apt-get update -qq >/dev/null
apt-get install -y -qq --no-install-recommends build-essential autoconf automake libtool pkg-config \
	ca-certificates curl libmnl-dev libnetfilter-queue-dev libnetfilter-conntrack-dev >/dev/null

mkdir -p "$CACHE" "$OUT"
tarball=$CACHE/ndpi-$NDPI_VERSION.tar.gz
[[ -f $tarball ]] || curl -fsSL -o "$tarball" "https://github.com/ntop/nDPI/archive/refs/tags/$NDPI_VERSION.tar.gz"
echo "$NDPI_SHA256  $tarball" | sha256sum -c --quiet

work=$(mktemp -d)
tar xzf "$tarball" -C "$work"
cd "$work/nDPI-$NDPI_VERSION"
./autogen.sh >/dev/null 2>&1
./configure --with-only-libndpi --prefix=/usr/local >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
lib=$(readlink -f /usr/local/lib/libndpi.so)
soname=$(objdump -p "$lib" | awk '/SONAME/ {print $2}')
install -m 644 "$lib" "$OUT/$soname"
strip --strip-unneeded "$OUT/$soname"
install -m 644 COPYING "$OUT/nDPI-COPYING"

cd "$SRC/appidd"
cc -O2 -Wall -Wextra -o "$OUT/appidd" appidd.c \
	-I/usr/local/include -L/usr/local/lib -lndpi \
	$(pkg-config --cflags --libs libmnl libnetfilter_queue libnetfilter_conntrack) -lm \
	-Wl,-rpath,$LIBDIR
strip "$OUT/appidd"
LD_LIBRARY_PATH=/usr/local/lib "$OUT/appidd" --catalog >"$OUT/catalog.json"
echo "appidd built: nDPI $NDPI_VERSION ($soname), $(grep -c '"id"' "$OUT/catalog.json") applications"
