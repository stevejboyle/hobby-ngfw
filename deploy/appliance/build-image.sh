#!/usr/bin/env bash
# Runs inside a privileged linux/amd64 Debian container (see build.sh).
# Starts from Debian's official "generic" cloud image, customises it in a
# chroot, and packages it as a VMware OVA.
set -euo pipefail

VERSION=${VERSION:-dev}
SRC=/src
OUT=$SRC/build/appliance
CACHE=$SRC/build/cache
WORK=$(mktemp -d)
MNT=$WORK/mnt
NAME=sjb-os
DISK_GB=8
IMG_URL=https://cloud.debian.org/images/cloud/trixie/latest
IMG=debian-13-generic-amd64.qcow2

cleanup() {
	set +e
	for m in run sys proc dev/pts dev; do umount "$MNT/$m" 2>/dev/null; done
	umount "$MNT" 2>/dev/null
	[[ -n ${LOOP:-} ]] && losetup -d "$LOOP" 2>/dev/null
	rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> tools"
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
	qemu-utils cloud-guest-utils gdisk e2fsprogs util-linux curl ca-certificates xz-utils libxml2-utils >/dev/null

echo "==> base image"
mkdir -p "$CACHE"
curl -fsSL -o "$CACHE/SHA512SUMS" "$IMG_URL/SHA512SUMS"
if ! (cd "$CACHE" && grep " $IMG\$" SHA512SUMS | sha512sum -c --status 2>/dev/null); then
	curl -fL --progress-bar -o "$CACHE/$IMG" "$IMG_URL/$IMG"
	(cd "$CACHE" && grep " $IMG\$" SHA512SUMS | sha512sum -c)
fi

echo "==> expand to ${DISK_GB} GB"
RAW=$WORK/disk.raw
qemu-img convert -O raw "$CACHE/$IMG" "$RAW"
qemu-img resize -f raw "$RAW" "${DISK_GB}G" >/dev/null
sgdisk -e "$RAW" >/dev/null
growpart "$RAW" 1 >/dev/null
read -r START SECTORS < <(partx -g -o START,SECTORS -n 1 "$RAW")
LOOP=$(losetup -f --show -o $((START * 512)) --sizelimit $((SECTORS * 512)) "$RAW")
e2fsck -fy "$LOOP" >/dev/null || true
resize2fs "$LOOP" >/dev/null

echo "==> customise root filesystem"
mkdir -p "$MNT"
mount "$LOOP" "$MNT"
for m in dev dev/pts proc sys run; do mount --bind "/$m" "$MNT/$m"; done
# The image's resolv.conf may be a symlink into /run; swap in a real file.
mv "$MNT/etc/resolv.conf" "$WORK/resolv.conf.orig"
cp /etc/resolv.conf "$MNT/etc/resolv.conf"

in_root() { chroot "$MNT" /usr/bin/env DEBIAN_FRONTEND=noninteractive "$@"; }
in_root apt-get update -qq
in_root apt-get install -y -qq --no-install-recommends \
	nftables conntrack libnetfilter-queue1 open-vm-tools cloud-guest-utils sudo openssl curl openssh-server ca-certificates >/dev/null
# What upgrade bundles ship to older appliances, installed here directly:
# FRR (BGP/OSPF), Kea (DHCP) and Suricata (IPS). ngfwd starts what the
# config uses; Debian's own Suricata unit must never run (sjb-ips does).
in_root systemctl mask -q suricata.service
in_root apt-get install -y -qq --no-install-recommends frr frr-pythontools kea-dhcp4-server suricata >/dev/null
in_root apt-get purge -y -qq cloud-init netplan.io ifupdown >/dev/null 2>&1 || true
in_root apt-get autoremove -y -qq --purge >/dev/null
rm -rf "$MNT/etc/cloud" "$MNT/var/lib/cloud" "$MNT"/etc/netplan/* "$MNT"/etc/network/interfaces.d/*
rm -f "$MNT"/etc/systemd/network/*

# VMware storage drivers must be in the initramfs whatever MODULES= says.
printf 'vmw_pvscsi\nmptspi\nmptsas\nahci\n' >>"$MNT/etc/initramfs-tools/modules"
in_root update-initramfs -u >/dev/null

cp -r "$SRC/deploy/appliance/rootfs/." "$MNT/"
install -m 755 "$OUT/bin/ngfwd" "$OUT/bin/fwctl" "$OUT/bin/tlsd" "$OUT/appidd/appidd" "$MNT/usr/local/sbin/"
install -d "$MNT/usr/share/sjb-os/lib" "$MNT/usr/share/sjb-os/appid" "$MNT/usr/share/sjb-os/licenses"
install -m 644 "$OUT"/appidd/libndpi.so.* "$MNT/usr/share/sjb-os/lib/"
install -m 644 "$OUT/appidd/catalog.json" "$MNT/usr/share/sjb-os/appid/"
install -m 644 "$OUT/appidd/nDPI-COPYING" "$MNT/usr/share/sjb-os/licenses/"
install -m 644 "$SRC/LICENSE" "$SRC/NOTICE" "$SRC/THIRD_PARTY_NOTICES.md" "$MNT/usr/share/sjb-os/licenses/"
# Corresponding source of the image: build.sh's manifest (SJB-OS, nDPI, Go)
# plus every installed Debian package with its source package and version.
{
	cat "$OUT/sources-base.txt"
	echo "# Debian packages installed in the image (source at snapshot.debian.org)"
	in_root dpkg-query -W -f='deb ${Package} ${Version} ${source:Package} ${source:Version}\n'
} >"$MNT/usr/share/sjb-os/licenses/SOURCES-image.txt"
cp "$MNT/usr/share/sjb-os/licenses/SOURCES-image.txt" "$OUT/sjb-os-$VERSION.ova-sources.txt"
install -d -m 755 "$MNT/var/lib/sjb-os"
# Root's SSH key: none in a release image (operators set one at deploy time).
# A lab build may carry its owner's (build.sh ROOT_KEY_FILE).
if [[ -f $OUT/dev-root-key.pub ]]; then
	install -d -m 700 "$MNT/etc/ngfw"
	install -m 600 "$OUT/dev-root-key.pub" "$MNT/etc/ngfw/root_authorized_keys"
fi
chmod 755 "$MNT/usr/local/sbin/ngfw-firstboot" "$MNT/usr/local/sbin/ngfw-console" "$MNT/usr/local/sbin/sjb-cli" \
	"$MNT/usr/local/sbin/sjb-migrate" "$MNT/usr/local/sbin/sjb-decrypt-net" "$MNT/etc/update-motd.d/10-sjb"
echo "$VERSION" >"$MNT/etc/ngfw-version"

# SJB-OS branding. Only PRETTY_NAME changes in os-release: VMware Tools
# reports it to vSphere as the guest's full name, while ID/VERSION_ID stay
# Debian's so tools and apt keep recognising the OS.
OSREL=$(readlink -f "$MNT/etc/os-release")
OSREL=$MNT${OSREL#"$MNT"}
sed -i "s/^PRETTY_NAME=.*/PRETTY_NAME=\"SJB-OS $VERSION (Stops Junk at the Border; Debian 13 underneath)\"/" "$OSREL"
# Replace Debian's login boilerplate with SJB-OS's message of the day.
rm -f "$MNT/etc/update-motd.d/10-uname"
: >"$MNT/etc/motd"

# No sudo: admin gets the captive CLI (sjb-migrate sets it up when ngfwd
# first starts, the same way upgrades from older versions get it).
in_root useradd -m -s /bin/bash -c "SJB-OS administrator" admin
in_root passwd -l admin >/dev/null
in_root systemctl enable -q systemd-networkd ssh open-vm-tools ngfw-firstboot ngfwd ngfw-console
# nftables.service flushes the whole ruleset on (re)start; ngfwd owns it.
in_root systemctl mask -q nftables.service

# Per-instance identity is generated at first boot.
rm -f "$MNT"/etc/ssh/ssh_host_*
: >"$MNT/etc/machine-id"
rm -f "$MNT/var/lib/dbus/machine-id"
in_root apt-get clean
rm -rf "$MNT"/var/lib/apt/lists/* "$MNT"/tmp/* "$MNT"/var/log/*.log

echo "==> checks"
# Capture first: with pipefail, `lsinitramfs | grep -q` fails when grep
# exits early and lsinitramfs gets SIGPIPE.
INITRD_FILES=$(in_root sh -c 'lsinitramfs /boot/initrd.img-*')
for drv in vmw_pvscsi vmxnet3; do
	grep -q "/$drv.ko" <<<"$INITRD_FILES" && echo "initramfs has $drv" ||
		{ echo "ERROR: $drv missing from initramfs; the VM would not boot on VMware"; exit 1; }
done
grep -q '^PRETTY_NAME="SJB-OS' "$MNT/etc/os-release" && echo "os-release: $(grep ^PRETTY_NAME "$MNT/etc/os-release")" ||
	{ echo "ERROR: os-release not branded"; exit 1; }
[[ ! -e $MNT/usr/share/sjb-os/root-keys ]] || { echo "ERROR: the image has the old shipped root key directory"; exit 1; }
if [[ -f $OUT/dev-root-key.pub ]]; then
	echo "root login key: $(awk '/^ssh-/ {print $NF}' "$MNT/etc/ngfw/root_authorized_keys" | xargs) (DEVELOPMENT IMAGE: never publish)"
else
	[[ ! -e $MNT/etc/ngfw/root_authorized_keys ]] && echo "root login key: none (set at deploy time)" ||
		{ echo "ERROR: a release image must not carry a root key"; exit 1; }
fi
ls "$MNT"/usr/share/sjb-os/upgrade-keys/*.pub >/dev/null 2>&1 && echo "upgrade keys: $(cat "$MNT"/usr/share/sjb-os/upgrade-keys/*.pub | awk '{print $3}' | xargs)" ||
	{ echo "ERROR: no upgrade signing key in the image"; exit 1; }
for f in usr/local/sbin/ngfwd usr/local/sbin/fwctl usr/sbin/nft usr/sbin/conntrack usr/bin/vmware-rpctool usr/bin/systemd-run usr/local/sbin/sjb-cli usr/local/sbin/sjb-migrate etc/update-motd.d/10-sjb; do
	[[ -x $MNT/$f ]] || { echo "ERROR: missing /$f"; exit 1; }
done
echo "kernel: $(ls "$MNT"/boot/vmlinuz-* | xargs -n1 basename)"

rm "$MNT/etc/resolv.conf"
mv "$WORK/resolv.conf.orig" "$MNT/etc/resolv.conf"
fstrim "$MNT" >/dev/null 2>&1 || true
for m in run sys proc dev/pts dev; do umount "$MNT/$m"; done
umount "$MNT"
losetup -d "$LOOP"
LOOP=

echo "==> package OVA"
PKG=$WORK/pkg
mkdir -p "$PKG"
DISK=$NAME-disk1.vmdk
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized,adapter_type=lsilogic "$RAW" "$PKG/$DISK"
sed -e "s|@DISK@|$DISK|" -e "s|@DISK_SIZE@|$(stat -c %s "$PKG/$DISK")|" \
	-e "s|@CAPACITY_GB@|$DISK_GB|" -e "s|@VERSION@|$VERSION|g" \
	"$SRC/deploy/appliance/sjb-os.ovf.in" >"$PKG/$NAME.ovf"
# Validate the descriptor against the DMTF OVF 1.1 schema (what vSphere's
# OVF parser implements), with the schema's imports pointed at local copies.
XSD=$WORK/xsd
mkdir -p "$XSD"
curl -fsSL -o "$XSD/ovf.xsd" https://schemas.dmtf.org/ovf/envelope/1/dsp8023_1.1.0.xsd
curl -fsSL -o "$XSD/xml.xsd" https://www.w3.org/2001/xml.xsd
curl -fsSL -o "$XSD/common.xsd" https://schemas.dmtf.org/wbem/wscim/1/common.xsd
curl -fsSL -o "$XSD/vssd.xsd" https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2.22.0/CIM_VirtualSystemSettingData.xsd
curl -fsSL -o "$XSD/rasd.xsd" https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2.22.0/CIM_ResourceAllocationSettingData.xsd
sed -i -e 's#http://www.w3.org/2001/xml.xsd#xml.xsd#' \
	-e 's#http://schemas.dmtf.org/wbem/wscim/1/common.xsd#common.xsd#' \
	-e 's#http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2.22.0/CIM_VirtualSystemSettingData.xsd#vssd.xsd#' \
	-e 's#http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2.22.0/CIM_ResourceAllocationSettingData.xsd#rasd.xsd#' \
	"$XSD"/*.xsd
xmllint --noout --schema "$XSD/ovf.xsd" "$PKG/$NAME.ovf"
grep -q '<vssd:VirtualSystemType>vmx-20</vssd:VirtualSystemType>' "$PKG/$NAME.ovf" &&
	echo "OVF targets vSphere 8 (hardware version 20)" ||
	{ echo "ERROR: OVF is not hardware version 20"; exit 1; }
(cd "$PKG" && for f in "$NAME.ovf" "$DISK"; do
	echo "SHA256($f)= $(sha256sum "$f" | cut -d' ' -f1)"
done >"$NAME.mf")
# OVA = tar with the descriptor first.
OVA=$OUT/$NAME-$VERSION.ova
tar --format=ustar -cf "$OVA" -C "$PKG" "$NAME.ovf" "$NAME.mf" "$DISK"
# Also keep the raw disk for local boot tests.
mv "$RAW" "$OUT/$NAME-$VERSION.raw"
echo "==> wrote $OVA"
