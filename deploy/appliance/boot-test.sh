#!/usr/bin/env bash
# Boot the built appliance disk in QEMU with VMware's device models (pvscsi
# disk, three vmxnet3 NICs) and check first boot end to end. No VMware needed.
# QEMU's software emulation is slow on Apple Silicon; allow several minutes.
#
# Needs qemu-system-x86_64, sshpass, curl, python3, and Go plus the upgrade
# signing key for the upgrade checks (run it inside `nix develop`).
# Usage: deploy/appliance/boot-test.sh build/appliance/sjb-os-<v>.raw [NEW.upgrade]
#   With NEW.upgrade, the image is upgraded to it right after first boot and
#   every check then runs against the new version (for bundle-only builds).
set -uo pipefail

RAW=${1:?usage: boot-test.sh DISK.raw [NEW.upgrade]}
NEWBUNDLE=${2:-}
WORK=$(mktemp -d)
LOG=$WORK/console.log
SSH_PORT=${SSH_PORT:-2222}
API_PORT=${API_PORT:-18443}
UI_PORT=${UI_PORT:-18444}
SIGNING_KEY=${SIGNING_KEY:-$HOME/.config/sjb-os/upgrade-signing.key}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
FAILS=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }

# Root's deploy settings, as an operator would set them: a throwaway key and
# console password for this run, through QEMU's firmware config (images from
# 0.9.9 read it; older images ignore it and keep their built-in key).
ssh-keygen -q -t ed25519 -N '' -C sjb-boot-test -f "$WORK/root_key"
ROOTPW=$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 16)
qemu-system-x86_64 -m 4096 -smp 2 -cpu max -display none -serial "file:$LOG" \
	-fw_cfg "name=opt/sjb/root_ssh_key,file=$WORK/root_key.pub" -fw_cfg "name=opt/sjb/root_password,string=$ROOTPW" \
	-device pvscsi,id=scsi0 \
	-drive "file=$RAW,format=raw,if=none,id=d0,snapshot=on" \
	-device scsi-hd,drive=d0,bus=scsi0.0 \
	-netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$API_PORT-:8443,hostfwd=tcp:127.0.0.1:$UI_PORT-:443" \
	-device vmxnet3,netdev=mgmt,addr=0x10 \
	-netdev user,id=inside,restrict=on,net=10.99.0.0/24 \
	-device vmxnet3,netdev=inside,addr=0x11 \
	-netdev user,id=outside,net=10.98.0.0/24 \
	-device vmxnet3,netdev=outside,addr=0x12 &
QEMU=$!
trap 'kill $QEMU 2>/dev/null; rm -rf "$WORK"' EXIT

# The console's ready line.
READY='SJB-OS ready'
echo "booting (console log: $LOG) ..."
for _ in $(seq 600); do
	grep -qE "$READY" "$LOG" 2>/dev/null && break
	kill -0 $QEMU 2>/dev/null || { echo "qemu exited"; cat "$LOG"; exit 1; }
	sleep 1
done
grep -qE "$READY" "$LOG" && pass "booted to '$(grep -oE "$READY" "$LOG" | head -1)'" || { fail "no 'SJB-OS ready' within 10 min"; tail -40 "$LOG"; exit 1; }
sleep 5 # let the serial getty print /etc/issue

echo "--- console ---"
sed -n '/^ *+-------/,/ready/p' "$LOG" | tr -d '\r'
grep -a "ngfw-firstboot:" "$LOG" | tr -d '\r'
echo "---------------"

PW=$(grep -ao 'initial password: [A-Za-z0-9]*' "$LOG" | tail -1 | awk '{print $3}')
[[ -n $PW ]] && pass "generated password shown on console" || fail "no password on console"

# Emulated boots are slow and sshd can drop early connections; retry only
# connection failures (ssh exit 255), never the remote command's own status.
SSHOPTS=(-q -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30)
retry255() {
	local rc
	for _ in 1 2 3 4 5; do
		"$@"
		rc=$?
		(( rc != 255 )) && return $rc
		sleep 3
	done
	return $rc
}
# root: the deploy-time key from 0.9.9 on; older base images carry the
# developer's key, offered by the SSH agent (1Password). System checks.
ROOTAUTH=(-i "$WORK/root_key" -o IdentitiesOnly=yes)
root_run() { retry255 ssh "${SSHOPTS[@]}" "${ROOTAUTH[@]}" -o BatchMode=yes -o PreferredAuthentications=publickey root@127.0.0.1 "$@"; }
# The admin account: password login, which lands in the captive CLI; "$*"
# is a CLI command.
cli_run() { retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" "$*"; }

for _ in $(seq 10); do root_run true && break; sleep 3; done
if root_run true; then
	DEPLOYKEY=1
	[[ $(root_run 'cat /etc/ngfw/root_authorized_keys') == *sjb-boot-test* && $(root_run 'ls /usr/share/sjb-os/root-keys 2>&1') == *"No such file"* ]] &&
		pass "root logs in with the key from the deploy settings (root_ssh_key); no root key ships in the image" ||
		fail "deploy-time root key: $(root_run 'ls -l /etc/ngfw/root_authorized_keys /usr/share/sjb-os/root-keys' 2>&1)"
else
	# An image from before 0.9.9: its built-in key, from the agent. The first
	# use may wait for approval in 1Password.
	DEPLOYKEY=0
	ROOTAUTH=()
	for _ in $(seq 20); do root_run true && break; sleep 3; done
	root_run true && pass "root logs in with the base image's built-in key (image before 0.9.9)" || fail "root key login"
fi
ADMIN=admin
st=$(cli_run show status)
[[ $st == *running_revision* ]] && pass "$ADMIN logs in to the captive CLI (show status)" || fail "CLI show status: $st"

if [[ -n $NEWBUNDLE ]]; then
	BASE=$(root_run cat /etc/ngfw-version)
	root_run "cat > /tmp/new.upgrade" <"$NEWBUNDLE"
	out=$(root_run fwctl upgrade apply /tmp/new.upgrade 2>&1)
	NEWV=$(root_run cat /etc/ngfw-version)
	[[ $NEWV != "$BASE" && $out == *"is running"* ]] &&
		pass "upgraded the $BASE image in place to $NEWV; the checks below test $NEWV" || fail "upgrading to the new bundle: $out"
	if [[ $DEPLOYKEY == 0 ]]; then
		# From an image before 0.9.9 (built-in root key): the upgrade keeps
		# root's access by moving the key to /etc/ngfw and drops the shipped
		# copy; rolling back puts it where the old version's sshd reads it.
		k=$(root_run 'test -s /etc/ngfw/root_authorized_keys && echo moved; ls /usr/share/sjb-os/root-keys 2>&1')
		[[ $k == moved*"No such file"* ]] &&
			pass "upgrade from $BASE moved root's key to /etc/ngfw and removed the shipped copy; root still logs in" || fail "root key move: $k"
		out=$(root_run fwctl upgrade rollback 2>&1)
		for _ in $(seq 15); do [[ $(root_run systemctl is-active ngfwd) == active ]] && break; sleep 2; done
		k=$(root_run 'cat /etc/ngfw-version; test -s /usr/share/sjb-os/root-keys/authorized_keys && echo restored')
		[[ $k == "$BASE"*restored* ]] && pass "rollback to $BASE: root's key back where $BASE reads it; root still logs in" ||
			fail "rollback root key: $k / $out"
		out=$(root_run fwctl upgrade apply /tmp/new.upgrade 2>&1)
		k=$(root_run 'cat /etc/ngfw-version; test -s /etc/ngfw/root_authorized_keys && echo moved; ls /usr/share/sjb-os/root-keys 2>&1')
		[[ $k == "$NEWV"*moved*"No such file"* ]] && pass "upgraded to $NEWV again: root's key moved again" || fail "re-upgrade root key: $k / $out"
	fi
	# Roll back to the base image's version after a commit, then upgrade
	# again: the rollback restores the config that was running at the
	# upgrade (as a new revision), not the later one.
	script=$'configure\nset application-group rbtest member [ youtube category:vpn ]\ncommit -m "boot test: before rollback to base"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	before=$(root_run 'cat /var/lib/ngfw/running')
	out=$(root_run fwctl upgrade rollback 2>&1)
	act=
	for _ in $(seq 15); do
		act=$(root_run systemctl is-active ngfwd)
		[[ $act == active ]] && break
		sleep 2
	done
	now=$(root_run 'cat /var/lib/ngfw/running')
	cfg=$(root_run "cat /var/lib/ngfw/revisions/\$(printf %06d \$(cat /var/lib/ngfw/running)).yaml")
	st=$(cli_run show status)
	[[ $(root_run cat /etc/ngfw-version) == "$BASE" && $act == active && $out == *"config: revision $now is the config that was running at the upgrade"* &&
		$now == $((before + 1)) && $cfg != *rbtest* && $st == *running_revision* ]] &&
		pass "rollback to $BASE: ngfwd starts on the config that was running at the upgrade (revision $now)" ||
		fail "rollback to base $BASE: ngfwd $act, revisions $before -> $now: $out"
	out=$(root_run fwctl upgrade apply /tmp/new.upgrade 2>&1)
	st=$(cli_run show status)
	[[ $(root_run cat /etc/ngfw-version) == "$NEWV" && $st == *running_revision* ]] &&
		pass "upgraded to $NEWV again" || fail "second upgrade: $out / $st"
fi
REV0=$(root_run fwctl status | grep -o '"running_revision": [0-9]*' | grep -o '[0-9]*$')
names=$(root_run "ip -br link" | awk '{print $1}' | tr '\n' ' ')
[[ $names == *mgmt* && $names == *inside* && $names == *outside* ]] &&
	pass "NICs renamed: $names" || fail "NIC names: $names"
root_run "ip -4 -br addr show inside" | grep -q 10.10.1.1/24 && pass "inside has 10.10.1.1/24" || fail "inside address"
root_run "ip route show default" | grep -q "dev outside" && pass "default route via outside" || fail "default route: $(root_run ip route show default)"
root_run "ip route show vrf vrf-mgmt default" | grep -q "dev mgmt" && pass "mgmt default route isolated in vrf-mgmt" || fail "mgmt vrf route"
rev=$(root_run fwctl status | grep -o '"running_revision": [0-9]*' | grep -o '[0-9]*$')
[[ $rev == 1 || ( -n $NEWBUNDLE && $rev == "$REV0" ) ]] && pass "running revision $rev (initial config committed as revision 1)" || fail "running revision: $rev"
root_run nft list chain inet ngfw postrouting | grep -q 'oifname "outside" counter.*masquerade' &&
	pass "NAT inside -> outside in ruleset" || fail "NAT missing"
[[ $(root_run readlink /etc/systemd/system/nftables.service) == /dev/null ]] &&
	pass "nftables.service masked (cannot flush ngfwd's ruleset)" || fail "nftables.service not masked"
# Capture, don't pipe: is-active exits 3 for inactive units, which pipefail
# would turn into a failed check.
state=$(root_run systemctl is-active nftables.service)
[[ $state == inactive ]] && pass "nftables.service not running" || fail "nftables.service state: $state"

KEY=$(root_run cat /etc/ngfw/api-keys | awk '/^admin/ {print $3}')
code=$(curl -sk -o /dev/null -w '%{http_code}' -H "X-API-Key: $KEY" \
	-d '{"ip":"10.10.1.50","tags":["quarantine"],"ttl":60}' "https://127.0.0.1:$API_PORT/api/v1/tags/register")
[[ $code == 200 ]] && pass "tag API over HTTPS on mgmt (200)" || fail "tag API returned $code"
root_run nft list set inet ngfw dag_quarantine | grep -q 10.10.1.50 && pass "registration reached the kernel set" || fail "set missing 10.10.1.50"
code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:$API_PORT/api/v1/tags")
[[ $code == 401 ]] && pass "tag API rejects missing key (401)" || fail "no-key returned $code"

# --- SJB-OS branding ------------------------------------------------------------
hdr=$(curl -skI -H "X-API-Key: $KEY" "https://127.0.0.1:$API_PORT/api/v1/tags" | tr -d '\r' | grep -i '^x-sjb-os:')
[[ $hdr == *"Stops Junk at the Border"* ]] && pass "API answers with $hdr" || fail "no X-SJB-OS header"
root_run "grep -q '^PRETTY_NAME=\"SJB-OS' /etc/os-release" && pass "os-release says SJB-OS" || fail "os-release not branded"
root_run "grep -q 'Apache License' /usr/share/sjb-os/licenses/LICENSE && grep -q 'marks of SJB Consulting' /usr/share/sjb-os/licenses/NOTICE && grep -q LGPL /usr/share/sjb-os/licenses/THIRD_PARTY_NOTICES.md && grep -q '^ndpi ' /usr/share/sjb-os/licenses/SOURCES*.txt" &&
	pass "license, notice, third-party notices and the corresponding-source manifest in /usr/share/sjb-os/licenses" || fail "license files missing: $(root_run 'ls /usr/share/sjb-os/licenses' 2>&1)"
root_run "grep -q 'Stops Junk at the Border' /etc/issue && grep -q 'login: admin' /etc/issue" && pass "console login banner has the SJB-OS mark" || fail "/etc/issue not branded: $(root_run cat /etc/issue)"
# The client only prints the server's banner at LogLevel INFO or above.
banner=$(sshpass -p "$PW" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o LogLevel=INFO "$ADMIN@127.0.0.1" true 2>&1)
sshd_banner=$(root_run sshd -T | grep -i '^banner')
echo "  sshd effective: $sshd_banner"
[[ $banner == *"turned back at the border"* ]] && pass "SSH pre-login banner shown" || fail "SSH banner missing"
motd=$(root_run run-parts /etc/update-motd.d)
[[ $motd == *"On duty: revision $REV0,"* && $motd == *"1 host(s) in quarantine"* ]] &&
	pass "MOTD shows live status" || fail "MOTD: $(echo "$motd" | grep -i duty | head -1)"
sjb=$(cli_run sjb)
[[ $sjb == *"Revision $REV0 is on duty"* ]] && pass "fwctl sjb has a word from the border guard" || fail "fwctl sjb: $sjb"

# --- captive CLI and root access ---------------------------------------------------
out=$(cli_run bash -c id 2>&1)
[[ $out == *"unknown command"* && $out != *uid=* ]] && pass "CLI refuses a shell (bash -c id)" || fail "CLI shell escape: $out"
out=$(cli_run sudo -i 2>&1)
[[ $out == *"unknown command"* ]] && pass "CLI refuses sudo" || fail "CLI sudo: $out"
groups=$(root_run id -nG "$ADMIN")
[[ $groups == *sjbadm* && $groups != *sudo* ]] && pass "$ADMIN is in sjbadm, not sudo ($groups)" || fail "$ADMIN groups: $groups"
[[ $(root_run getent passwd "$ADMIN" | cut -d: -f7) == /usr/lib/sjb-os/login-shell ]] &&
	pass "$ADMIN's console login shell is the CLI shim" || fail "$ADMIN shell: $(root_run getent passwd "$ADMIN")"
echo hello >"$WORK/hello.txt"
sshpass -p "$PW" scp -q -P "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
	-o PubkeyAuthentication=no "$WORK/hello.txt" "$ADMIN@127.0.0.1":/tmp/ 2>/dev/null &&
	fail "scp as $ADMIN succeeded" || pass "file transfer as $ADMIN refused"
sshpass -p "$PW" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no -o BatchMode=no root@127.0.0.1 true 2>/dev/null &&
	fail "root password login over SSH succeeded" || pass "root cannot log in over SSH with a password"
if [[ $DEPLOYKEY == 1 ]]; then
	# The console password is the one from the deploy settings (checked
	# against the shadow hash; root can't use a password over SSH).
	sshpass -p "$ROOTPW" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no -o BatchMode=no root@127.0.0.1 true 2>/dev/null &&
		fail "root logged in over SSH with the console password" || true
	m=$(root_run "perl -e 'my \$h=(getpwnam(\"root\"))[1]; print crypt(\$ARGV[0], \$h) eq \$h ? \"match\" : \"no\"' '$ROOTPW'")
	[[ $(root_run "passwd -S root") == *" P "* && $m == match ]] &&
		pass "root console password is the one from the deploy settings (root_password); refused over SSH" || fail "root console password: $m"
else
	root_run "passwd -S root" | grep -q ' P ' && pass "root console password kept from the base image" || fail "root console password"
fi
cli_run show running >"$WORK/running.yaml"
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" load <"$WORK/running.yaml")
[[ $out == *"candidate updated"* ]] && pass "config loads through the CLI from stdin" || fail "CLI load: $out"
keys=$(cli_run show api-keys)
[[ $keys == *"$KEY"* ]] && pass "CLI shows the tag API key (root-only file)" || fail "show api-keys: $keys"

# --- configuration mode ------------------------------------------------------------
script=$'configure\nset address cli-test cidr 192.0.2.77\nset rule cli-rule from inside to outside source cli-test\nset rule cli-rule action deny log yes\nmove rule cli-rule top\nshow rule cli-rule\ncommit -m "from configure mode"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
first=$(root_run nft list chain inet ngfw forward | grep -m1 'comment "rule:' | grep -o 'rule:[a-z-]*')
[[ $out == *"committed revision"* && $first == rule:cli-rule ]] &&
	pass "configure mode: set, move to top, commit (cli-rule is first in the ruleset)" || fail "configure mode: $first / $out"
script=$'configure\nrename address cli-test cli-host\ndelete rule cli-rule\ndelete address cli-host\ncommit -m "cleanup"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
[[ $out == *"committed revision"* && $(cli_run show running) != *cli-* ]] &&
	pass "configure mode: rename and delete, committed" || fail "configure cleanup: $out"

# --- publishing a server (port forward, static NAT) -------------------------------
script=$'configure\nset address nat-srv cidr 10.10.1.77\nset address nat-pub cidr 192.0.2.88\nset nat bt-fwd type port-forward interface outside protocol tcp public-port 8443 server nat-srv server-port 443\nset nat bt-static type static interface outside public-address nat-pub server nat-srv\ncommit -m "boot test: nat"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
pre=$(root_run nft list chain inet ngfw prerouting_nat 2>&1)
oa=$(root_run "ip -4 -o addr show dev outside")
[[ $out == *"committed revision"* && $out == *'nat "bt-fwd": no allow rule'* && $pre == *"dnat ip to 10.10.1.77:443"* && $pre == *"dnat ip to 10.10.1.77 "* ]] &&
	pass "port forward and static NAT committed in configure mode (warned: no allow rule)" || fail "nat commit: pre=[$pre] out=${out: -300}"
[[ $oa == *"192.0.2.88/32"*"outside:nat"* ]] && pass "static NAT's public address put on outside (label outside:nat)" || fail "nat address: [$oa]"
sn=$(cli_run show nat)
[[ $sn == *bt-fwd*tcp/8443* && $sn == *bt-static*on* ]] && pass "show nat lists the port forward and the static NAT" || fail "show nat: $sn"
script=$'configure\ndelete nat bt-fwd\ndelete nat bt-static\ndelete address nat-srv\ndelete address nat-pub\ncommit -m "boot test: nat cleanup"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
oa=$(root_run "ip -4 -o addr show dev outside")
[[ $out == *"committed revision"* && $oa != *192.0.2.88* ]] && pass "NAT entries deleted: the public address is off outside" || fail "nat cleanup: [$oa] ${out: -200}"

# --- web UI -----------------------------------------------------------------------
JAR=$WORK/cookies
UI="https://127.0.0.1:$UI_PORT"
code=$(curl -sk -o /dev/null -w '%{http_code}' "$UI/")
[[ $code == 200 ]] && pass "web UI page served over HTTPS on mgmt" || fail "web UI / returned $code"
login=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' \
	-d "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" "$UI/ui/api/login")
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf",""))' <<<"$login" 2>/dev/null)
[[ -n $CSRF ]] && pass "web UI login with the first-boot password" || fail "web UI login: $login"
ui() { curl -sk -b "$JAR" -H "X-SJB-CSRF: $CSRF" -H 'Content-Type: application/json' "$@"; }
cand=$(ui "$UI/ui/api/config/candidate")
newcfg=$(python3 -c 'import json,sys
c=json.load(sys.stdin)
c["rules"].insert(0,{"name":"ui-block-telnet","from":["inside"],"to":["outside"],"source":[],"destination":[],"application":[],"service":["telnet"],"action":"deny","log":True})
c["services"]=(c.get("services") or [])+[{"name":"telnet","protocol":"tcp","ports":"23"}]
print(json.dumps(c))' <<<"$cand")
put=$(ui -X PUT -d "$newcfg" -w ' %{http_code}' "$UI/ui/api/config/candidate")
commit=$(ui -d '{"message":"boot test via web UI","confirm_minutes":5}' "$UI/ui/api/commit")
confirm=$(ui -d '{}' -w '%{http_code}' -o /dev/null "$UI/ui/api/confirm")
[[ $put == *200 && $commit == *confirm_by* && $confirm == 200 ]] &&
	pass "rule added, committed with confirm and confirmed through the web UI" || fail "UI edit: put=$put commit=$commit confirm=$confirm"
root_run nft list chain inet ngfw forward | grep -q 'ui-block-telnet' &&
	pass "UI-added rule is in the kernel ruleset" || fail "UI rule not in ruleset"
root_run fwctl revisions | grep -q "\"author\": \"web:$ADMIN\"" && pass "revision authored web:$ADMIN" || fail "revision author"

# --- logs -------------------------------------------------------------------------
# No client sits behind inside in QEMU, so write a line in exactly the form the
# ruleset's log statements produce; the compiler golden tests pin that form.
root_run "echo 'ngfw boot-test-rule deny IN=inside OUT=outside SRC=10.10.1.99 DST=192.0.2.1 LEN=60 PROTO=TCP SPT=40404 DPT=443 SYN' > /dev/kmsg"
sleep 2
tl=$(ui "$UI/ui/api/logs/traffic?q=boot-test-rule")
[[ $tl == *'"src":"10.10.1.99"'* && $tl == *'"dport":443'* && $tl == *'"action":"deny"'* ]] &&
	pass "traffic log in the web UI shows a data-plane entry" || fail "traffic log: $tl"
[[ $tl == *'"from":"'* && $tl == *'"to":"'* && $tl == *'"sport":40404'* && $tl == *'"flags":"SYN"'* && $tl == *'"len":60'* ]] &&
	pass "traffic log entries carry zones, ports, TCP flags and length" || fail "traffic log fields: $tl"
cols=$(ui "$UI/ui/api/logs/traffic/columns")
[[ $cols == *'"name":"sport"'* && $cols == *'"name":"app"'* && $cols == *'"default":['* ]] && pass "web UI gets the traffic log's column list" || fail "log columns: $cols"
out=$(cli_run show log traffic boot-test-rule)
[[ $out == *SPORT*DPORT* && $out == *10.10.1.99*40404*192.0.2.1*443* ]] && pass "CLI show log traffic shows it, ports in their own columns" || fail "show log traffic: $out"
tq=$(ui -G --data-urlencode "q=zone = inside and dst = 192.0.2.1 and dport = 443" "$UI/ui/api/logs/traffic")
tn=$(ui -G --data-urlencode "q=zone = inside and dst = 192.0.2.2" "$UI/ui/api/logs/traffic")
tb=$(ui -G --data-urlencode "q=zon = inside" -w ' %{http_code}' "$UI/ui/api/logs/traffic")
[[ $tq == *boot-test-rule* && $tn != *boot-test-rule* && $tb == *'unknown field'*400 ]] &&
	pass "log queries in the web UI: zone and destination match, a typo is a 400 with help" || fail "log query: $tq / $tn / $tb"
out=$(cli_run show log traffic where zone = inside and dst = 192.0.2.0/24 and not action = allow)
[[ $out == *boot-test-rule*10.10.1.99* ]] && pass "CLI show log traffic where QUERY" || fail "show log where: $out"
out=$(cli_run show log traffic boot-test-rule columns rule,src,sport,dport,flags,app)
[[ $out == *"RULE"*"SRC"*"SPORT"*"DPORT"*"FLAGS"*"APP"* && $out == *boot-test-rule*10.10.1.99*40404*443*SYN* && $out != *ACTION* ]] &&
	pass "CLI show log traffic columns picks the columns" || fail "show log traffic columns: $out"
sl=$(ui "$UI/ui/api/logs/system?q=commit")
[[ $sl == *'"source":"ngfwd"'* && $sl == *"author=web:$ADMIN"* ]] &&
	pass "system log shows commits with their author" || fail "system log: ${sl:0:300}"

# --- static routes ----------------------------------------------------------------
cand=$(ui "$UI/ui/api/config/candidate")
withroutes=$(python3 -c 'import json,sys
c=json.load(sys.stdin)
c["routes"]=[{"name":"lab-net","destination":"10.20.0.0/16","gateway":"10.10.1.254","interface":"","table":""},
             {"name":"mgmt-net","destination":"192.0.2.0/24","gateway":"10.0.2.2","interface":"","table":"mgmt"}]
print(json.dumps(c))' <<<"$cand")
ui -X PUT -d "$withroutes" -o /dev/null "$UI/ui/api/config/candidate"
commit=$(ui -d '{"message":"boot test: static routes"}' "$UI/ui/api/commit")
r1=$(root_run ip -4 route show 10.20.0.0/16)
r2=$(root_run ip -4 route show table 100 192.0.2.0/24)
echo "  kernel: [$r1] [table 100: $r2]"
[[ $commit == *revision* && $r1 == *"via 10.10.1.254 dev inside proto sjb"* && $r2 == *"via 10.0.2.2 dev mgmt proto sjb"* ]] &&
	pass "static routes committed into the forwarding and management tables" || fail "routes: commit=$commit main=[$r1] mgmt=[$r2]"
out=$(cli_run show routes)
[[ $out == *lab-net* && $out == *mgmt-net* && $out != *"NOT INSTALLED"* ]] && pass "CLI show routes lists them as installed" || fail "show routes: $out"
root_run ip -4 route del 10.20.0.0/16 table main
for _ in $(seq 15); do sleep 2; [[ -n $(root_run ip -4 route show 10.20.0.0/16) ]] && break; done
[[ -n $(root_run ip -4 route show 10.20.0.0/16) ]] && pass "a deleted static route is put back by ngfwd" || fail "route not restored"
ui -X PUT -d "$cand" -o /dev/null "$UI/ui/api/config/candidate"
ui -d '{"message":"boot test: remove routes"}' -o /dev/null "$UI/ui/api/commit"
[[ -z $(root_run ip -4 route show 10.20.0.0/16) && -z $(root_run ip -4 route show table 100 192.0.2.0/24) ]] &&
	pass "removing routes from the config removes them from the kernel" || fail "routes still present after removal"
[[ -n $(root_run ip -4 route show default) && -n $(root_run ip -4 route show table 100 default) ]] &&
	pass "deploy-time default routes untouched" || fail "default routes missing"

# A configured default route overrides the deployment's; removing it brings the
# deployment's back (here a DHCP default, deleted by hand to stand in for a
# static Gateway= default that ours replaced).
gw=$(root_run "ip -4 route show default dev outside" | awk '/via/ {print $3; exit}')
withdef=$(python3 -c 'import json,sys
c=json.load(sys.stdin)
c["routes"]=[{"name":"internet","destination":"0.0.0.0/0","gateway":sys.argv[1],"interface":"outside","table":""}]
print(json.dumps(c))' "$gw" <<<"$cand")
ui -X PUT -d "$withdef" -o /dev/null "$UI/ui/api/config/candidate"
commit=$(ui -d '{"message":"boot test: default route"}' "$UI/ui/api/commit")
first=$(root_run "ip -4 route show default" | head -1)
[[ $commit == *revision* && $first == *"via $gw dev outside proto sjb"* ]] &&
	pass "a configured default route ($gw) takes over from the deployment's" || fail "default route: commit=$commit first=[$first]"
root_run "ip -4 route del default proto dhcp" || true
ui -X PUT -d "$cand" -o /dev/null "$UI/ui/api/config/candidate"
ui -d '{"message":"boot test: remove default route"}' -o /dev/null "$UI/ui/api/commit"
for _ in $(seq 15); do d=$(root_run "ip -4 route show default"); [[ $d == *"dev outside"* && $d != *"proto sjb"* ]] && break; sleep 2; done
[[ $d == *"dev outside"* && $d != *"proto sjb"* ]] &&
	pass "removing it restores the deployment's default route" || fail "default route after removal: [$d]"

# A configured outside address takes over from the deployment's DHCP (with a
# configured default route, as when DHCP gets no lease); removing both brings
# DHCP back.
script=$'configure\nset interface outside address 10.98.0.50/24\nset route internet destination 0.0.0.0/0 gateway 10.98.0.2 interface outside\ncommit -m "boot test: static outside"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
oa=$(root_run "ip -4 -o addr show dev outside" | awk '{print $4}' | tr '\n' ' ')
first=$(root_run "ip -4 route show default" | head -1)
[[ $out == *"committed revision"* && $oa == "10.98.0.50/24 " && $first == *"via 10.98.0.2 dev outside proto sjb"* ]] &&
	pass "configured outside address replaces DHCP, with its default route" || fail "static outside: addr=[$oa] default=[$first] out=${out: -300}"
si=$(cli_run show interfaces)
[[ $si == *"10.98.0.50/24"*applied* ]] && pass "show interfaces lists the configured address as applied" || fail "show interfaces: $si"
ov=$(root_run cat /etc/systemd/network/10-outside-sjb.network)
cli_run ping 10.98.0.2 1 >/dev/null 2>&1 # make an ARP entry for the gateway
arp=$(cli_run show arp outside)
[[ $ov == *"DuplicateAddressDetection=ipv4"* && $arp == *"10.98.0.2 lladdr"* && $(root_run sysctl -n net.ipv4.conf.all.arp_notify) == 1 ]] &&
	pass "configured address is announced (conflict detection on, arp_notify on); show arp sees the gateway" || fail "announce/arp: arp=[$arp] notify=$(root_run sysctl -n net.ipv4.conf.all.arp_notify)"
la=$(ui "$UI/ui/api/arp")
[[ $la == *'"address":"10.98.0.2"'* ]] && pass "web UI ARP table lists the gateway" || fail "ui arp: ${la:0:200}"
# An upgrade that changes the override's format (r05 -> r06) must not stop
# ngfwd from starting: systemd gives it seconds to open its socket, so the
# start only rewrites the file and the periodic pass applies it.
root_run "sed -i '/^\\[Address\\]/,\$d; /^DHCP=no/a Address=10.98.0.50/24' /etc/systemd/network/10-outside-sjb.network && networkctl reload"
root_run systemctl restart ngfwd && act=$(root_run systemctl is-active ngfwd)
# The periodic pass (every 10 s) reconfigures, then networkd's conflict
# detection takes several seconds (longer under emulation): allow a minute.
for _ in $(seq 30); do
	sleep 2
	ov=$(root_run cat /etc/systemd/network/10-outside-sjb.network)
	si=$(cli_run show interfaces)
	[[ $ov == *DuplicateAddressDetection* && $si == *"10.98.0.50/24"*applied* ]] && break
done
[[ $act == active && $ov == *DuplicateAddressDetection* && $si == *"10.98.0.50/24"*applied* && $si != *"NOT APPLIED"* ]] &&
	pass "ngfwd restarts promptly over an older-format override, then applies the new one" || fail "restart over old override: active=$act si=$si ov=$ov"
# The restart ended the web UI session: log in again.
login=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' -d "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" "$UI/ui/api/login")
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf",""))' <<<"$login" 2>/dev/null)
# An address another device already has is refused (the QEMU network's DNS
# address, 10.98.0.3, answers ARP).
script=$'configure\nset interface outside address 10.98.0.3/24\ncommit -m "boot test: conflicting address"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
si=$(cli_run show interfaces)
[[ $si == *"10.98.0.3/24"*"NOT APPLIED"* && $(root_run "ip -4 -o addr show dev outside") != *10.98.0.3/* ]] &&
	pass "an address already in use on the network is detected and not applied" || fail "conflict: $si"
ui -X PUT -d "$cand" -o /dev/null "$UI/ui/api/config/candidate"
ui -d '{"message":"boot test: outside back to DHCP"}' -o /dev/null "$UI/ui/api/commit"
for _ in $(seq 20); do
	oa=$(root_run "ip -4 -o addr show dev outside" | awk '{print $4}' | tr '\n' ' ')
	d=$(root_run "ip -4 route show default")
	[[ $oa == 10.98.0.* && $oa != *10.98.0.50/* && $d == *"proto dhcp"* ]] && break
	sleep 2
done
[[ $oa == 10.98.0.* && $oa != *10.98.0.50/* && $d == *"proto dhcp"* && -z $(root_run "ls /etc/systemd/network/10-outside-sjb.network 2>/dev/null") ]] &&
	pass "removing it brings back the deployment's DHCP address and default" || fail "outside after removal: addr=[$oa] default=[$d]"

# --- one password for SSH, console and web UI ------------------------------------
PW2=web-changed-$RANDOM-pass
out=$(ui -d "{\"current\":\"$PW\",\"new\":\"$PW2\"}" "$UI/ui/api/password")
st=$(retry255 sshpass -p "$PW2" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" show status)
[[ $out == *'"ok":true'* && $st == *running_revision* ]] &&
	pass "password changed in the web UI works for SSH" || fail "web UI password change: $out / $st"
sshpass -p "$PW" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" show status >/dev/null 2>&1 &&
	fail "old password still works over SSH" || pass "old password no longer works over SSH"
PW3=cli-changed-$RANDOM-pass
out=$(printf '%s\n%s\n%s\n' "$PW2" "$PW3" "$PW3" |
	retry255 sshpass -p "$PW2" ssh "${SSHOPTS[@]}" -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" passwd 2>&1)
code=$(curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
	-d "{\"user\":\"$ADMIN\",\"password\":\"$PW3\"}" "$UI/ui/api/login")
[[ $out == *"Password changed"* && $code == 200 ]] &&
	pass "password changed with the CLI's passwd works for the web UI" || fail "CLI passwd: $out (web login $code)"
PW=$PW3
# A password change ends the user's older web sessions (0.9.9-r09 on): check,
# then log in again.
code=$(ui -o /dev/null -w '%{http_code}' "$UI/ui/api/status")
[[ $code == 401 ]] && pass "the password change ended the older web session" || fail "old web session after a password change: $code"
login=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' -d "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" "$UI/ui/api/login")
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf",""))' <<<"$login" 2>/dev/null)

# --- VRFs and VLAN subinterfaces ---------------------------------------------------
before_vrf=$(ui "$UI/ui/api/config/candidate")
script=$'configure\nset vrf blue\nset vrf red\nset zone labs\nset interface inside.20 zone labs vrf blue address 172.16.20.1/24\nset interface inside.30 zone labs vrf red address 172.16.20.1/24\nset route blue-default vrf blue destination 0.0.0.0/0 gateway 172.16.20.254\nset route blue-to-red vrf blue destination 172.31.0.0/16 next-vrf red\ncommit -m "boot test: vrfs"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
v20=$(root_run ip -d -4 addr show inside.20)
vblue=$(root_run ip -d link show vrf-blue)
[[ $out == *"committed revision"* && $v20 == *"vlan protocol 802.1Q id 20"* && $v20 == *"master vrf-blue"* && $v20 == *"172.16.20.1/24"* && $vblue == *"vrf table 1001"* ]] &&
	pass "VRF blue and VLAN inside.20 created, enslaved and addressed" || fail "vrf/vlan: $out / $v20 / $vblue"
v30=$(root_run ip -4 addr show inside.30)
[[ $v30 == *"172.16.20.1/24"* && $(root_run ip -d link show inside.30) == *"master vrf-red"* ]] &&
	pass "the same address in VRF red (inside.30)" || fail "inside.30: $v30"
zones=$(root_run nft list chain inet ngfw vrf_zones 2>&1)
[[ $zones == *'"inside.20" : 1'* && $zones == *'"inside.30" : 2'* ]] && pass "each VRF has its own conntrack zone" || fail "ct zones: $zones"
rb=$(root_run ip -4 route show vrf vrf-blue)
[[ $rb == *"default via 172.16.20.254 dev inside.20 proto sjb"* && $rb == *"172.31.0.0/16 dev vrf-red proto sjb"* ]] &&
	pass "VRF default route and leak route installed in vrf blue" || fail "vrf blue routes: $rb"
sv=$(cli_run show vrf)
[[ $sv == *"blue"*"1001"*"inside.20"*"up"* && $sv == *"red"*"1002"*"inside.30"*"up"* ]] && pass "CLI show vrf lists both as up" || fail "show vrf: $sv"
root_run ip link del inside.20
for _ in $(seq 15); do sleep 2; [[ $(root_run ip -d -4 addr show inside.20 2>/dev/null) == *"master vrf-blue"*"172.16.20.1/24"* ]] && break; done
[[ $(root_run ip -d -4 addr show inside.20 2>/dev/null) == *"master vrf-blue"*"172.16.20.1/24"* ]] &&
	pass "a deleted VLAN subinterface is re-created in its VRF by ngfwd" || fail "inside.20 not restored"
ui -X PUT -d "$before_vrf" -o /dev/null "$UI/ui/api/config/candidate"
ui -d '{"message":"boot test: remove vrfs"}' -o /dev/null "$UI/ui/api/commit"
gone=$(root_run "ip link show inside.20; ip link show vrf-blue; ip link show vrf-red" 2>&1)
[[ $gone == *'"inside.20" does not exist'* && $gone == *'"vrf-blue" does not exist'* && $(root_run ip link show vrf-mgmt) == *vrf-mgmt* ]] &&
	pass "removing VRFs and VLANs from the config removes the devices (vrf-mgmt untouched)" || fail "removal: $gone"

# --- a client inside a VRF: may ping the firewall, may not reach its services ----------
root_run 'set -e
	ip netns add client
	ip link add vlab type veth peer name vpeer; ip link set vpeer netns client; ip link set vlab up
	ip -n client link set vpeer up
	ip -n client link add link vpeer name vpeer.40 type vlan id 40
	ip -n client addr add 172.16.40.2/24 dev vpeer.40; ip -n client link set vpeer.40 up
	ip -n client route add default via 172.16.40.1'
script=$'configure\nset vrf probe\nset zone probes\nset interface vlab zone probes\nset interface vlab.40 zone probes vrf probe address 172.16.40.1/24\ncommit -m "boot test: vrf client"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
sleep 3
root_run "ip netns exec client ping -c 2 -W 2 172.16.40.1" >/dev/null &&
	pass "a client in a VRF can ping the firewall" || fail "VRF client ping failed"
root_run "ip netns exec client timeout 5 bash -c 'echo > /dev/tcp/172.16.40.1/22'" 2>/dev/null &&
	fail "a client in a VRF reached the firewall's SSH" || pass "a client in a VRF can't reach the firewall's SSH (zone-to-firewall drop)"
drops=$(root_run nft list chain inet ngfw input | grep 'sdifname' | grep -o 'packets [0-9]*' | head -1)
[[ ${drops#packets } -gt 0 ]] && pass "the VRF drop rule counted it ($drops)" || fail "VRF drop rule didn't match: $drops"

# --- commit-confirmed survives an ngfwd restart ------------------------------------
revof() { grep -o '"running_revision": [0-9]*' | grep -o '[0-9]*$'; }
cand=$(ui "$UI/ui/api/config/candidate")
changed=$(python3 -c 'import json,sys
c=json.load(sys.stdin)
c["addresses"]=(c.get("addresses") or [])+[{"name":"pending-test","cidr":"192.0.2.99"}]
print(json.dumps(c))' <<<"$cand")
ui -X PUT -d "$changed" -o /dev/null "$UI/ui/api/config/candidate"
ui -d '{"message":"boot test: pending across restart","confirm_minutes":1}' -o /dev/null "$UI/ui/api/commit"
REVP=$(root_run fwctl status | revof)
up=$(ui -d '{}' -w ' %{http_code}' "$UI/ui/api/upgrade/start")
[[ $up == *"waiting for confirmation"*409 ]] && pass "upgrade refused while a commit awaits confirmation" || fail "upgrade during pending commit: $up"
root_run systemctl restart ngfwd
st=$(cli_run show status)
[[ $st == *confirm_by* && $(revof <<<"$st") == "$REVP" ]] &&
	pass "after an ngfwd restart the commit still awaits confirmation" || fail "after restart: $st"
misses=""
for _ in $(seq 50); do
	sleep 3
	out=$(root_run fwctl status 2>&1)
	rev=$(revof <<<"$out")
	[[ -z $rev ]] && { misses+=" [$out]"; continue; } # a status read that failed tells nothing
	[[ $rev != "$REVP" ]] && break
done
[[ -n $misses ]] && echo "note: fwctl status reads without a revision during the rollback wait:$misses"
st=$(cli_run show status)
[[ $rev == $((REVP + 1)) && $st != *confirm_by* && $(cli_run show running) != *pending-test* ]] &&
	pass "unconfirmed commit rolled back on time after the restart" || fail "rollback after restart: revision $rev, $st"
# ngfwd's restart ended the web session; log in again.
login=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' -d "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" "$UI/ui/api/login")
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf",""))' <<<"$login" 2>/dev/null)

# --- BGP and OSPF (FRR shipped in the bundle) ------------------------------------
if [[ -n $NEWBUNDLE ]]; then
	for _ in $(seq 90); do
		[[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' frr" 2>/dev/null) == installed ]] && break
		sleep 2
	done
fi
if [[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' frr" 2>/dev/null) == installed ]]; then
	pass "FRR installed on the appliance ($(root_run "dpkg-query -W -f='\${Version}' frr"))"
	# A peer router in a network namespace, joined to the firewall by a veth.
	root_run 'set -e
		ip netns add peer
		ip link add lab0 type veth peer name peer0; ip link set peer0 netns peer
		ip addr add 10.99.99.1/24 dev lab0; ip link set lab0 up
		ip -n peer addr add 10.99.99.2/24 dev peer0; ip -n peer link set peer0 up; ip -n peer link set lo up
		ip -n peer link add dummy0 type dummy; ip -n peer addr add 10.201.0.1/24 dev dummy0; ip -n peer link set dummy0 up
		mkdir -p /etc/frr/peer /var/run/frr/peer
		touch /etc/frr/peer/vtysh.conf; echo "hostname peer" > /etc/frr/peer/empty.conf
		cat > /etc/frr/peer/frr.conf <<CONF
frr defaults traditional
hostname peer
interface peer0
 ip ospf area 0.0.0.0
exit
interface dummy0
 ip ospf area 0.0.0.0
 ip ospf passive
exit
router bgp 65002
 bgp router-id 10.99.99.2
 no bgp ebgp-requires-policy
 no bgp network import-check
 neighbor 10.99.99.1 remote-as 65001
 address-family ipv4 unicast
  network 10.200.0.0/16
 exit-address-family
exit
router ospf
 ospf router-id 10.99.99.2
exit
CONF
		chown -R frr:frr /etc/frr/peer /var/run/frr/peer
		# Detach the daemons from this SSH session, or ssh waits on them forever.
		for d in zebra bgpd ospfd; do ip netns exec peer /usr/lib/frr/$d -N peer -d -F traditional -f /etc/frr/peer/empty.conf </dev/null >/dev/null 2>&1; done
		sleep 2
		ip netns exec peer vtysh -N peer -f /etc/frr/peer/frr.conf </dev/null >/dev/null 2>&1'
	script=$'configure\nset zone peering\nset interface lab0 zone peering address 10.99.99.1/24\nset routing default router-id 10.99.99.1 bgp-asn 65001 bgp-network 10.10.0.0/16 ospf yes\nset bgp-neighbor peer address 10.99.99.2 remote-as 65002\nset ospf-interface lab0 area 0\ncommit -m "boot test: bgp and ospf"\nexit\nexit\n'
	out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
	[[ $out == *"committed revision"* ]] && pass "BGP and OSPF configured in configure mode and committed" || fail "routing commit: $out"
	for _ in $(seq 60); do
		b=$(cli_run show bgp); o=$(cli_run show ospf)
		[[ $b == *Established* && $o == *Full* && -n $(root_run ip -4 route show 10.201.0.0/24 proto ospf) ]] && break
		sleep 3
	done
	[[ $b == *"10.99.99.2"*"65002"*Established* ]] && pass "BGP session to the peer Established (show bgp)" || fail "show bgp: $b"
	[[ $o == *"10.99.99.2"*Full* ]] && pass "OSPF adjacency Full (show ospf)" || fail "show ospf: $o"
	[[ -n $(root_run ip -4 route show 10.200.0.0/16 proto bgp) && -n $(root_run ip -4 route show 10.201.0.0/24 proto ospf) ]] &&
		pass "learned routes in the kernel: 10.200.0.0/16 by BGP, 10.201.0.0/24 by OSPF" || fail "kernel routes: $(root_run ip -4 route)"
	peer=$(root_run "ip netns exec peer vtysh -N peer -c 'show ip bgp json'" 2>/dev/null)
	[[ $peer == *'"10.10.0.0/16"'* ]] && pass "the peer received the firewall's announced 10.10.0.0/16" || fail "peer table: ${peer:0:300}"
	inp=$(root_run nft list chain inet ngfw input)
	[[ $inp == *'ip saddr 10.99.99.2 tcp dport 179 accept comment "bgp:peer"'* && $inp == *'iifname "lab0" meta l4proto ospf accept'* ]] &&
		pass "input chain opens BGP from the neighbor and OSPF on lab0 only" || fail "input chain: $inp"
	wb=$(ui "$UI/ui/api/routing/bgp")
	[[ $wb == *'"state":"Established"'* ]] && pass "web UI Routing view shows the session" || fail "UI routing: $wb"
	rib=$(cli_run show rib)
	[[ $rib == *"10.200.0.0/16"*bgp* ]] && pass "CLI show rib lists the BGP route" || fail "show rib: $rib"
	# A static default and a BGP default to the same next hop, with outside
	# on a configured address; removing the static must hand over to BGP
	# without touching outside (r04-r07 reconfigured outside, taking its
	# address down while conflict detection re-ran).
	root_run "ip netns exec peer vtysh -N peer -c 'conf t' -c 'router bgp 65002' -c 'address-family ipv4 unicast' -c 'neighbor 10.99.99.1 default-originate'" >/dev/null 2>&1
	script=$'configure\nset interface outside address 10.98.0.50/24\nset route bgpdef destination 0.0.0.0/0 gateway 10.99.99.2 interface lab0\ncommit -m "boot test: static default beside a BGP one"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	for _ in $(seq 30); do
		bd=$(root_run "vtysh -c 'show ip bgp 0.0.0.0/0'" 2>/dev/null)
		[[ $bd == *10.99.99.2* && -n $(root_run ip -4 route show default proto sjb) ]] && break
		sleep 2
	done
	# Watch outside's address on the VM while the static default is removed.
	root_run 'nohup sh -c "for i in \$(seq 40); do ip -4 -o addr show dev outside | grep -q 10.98.0.50/24 || echo gone; sleep 0.25; done > /run/outside-watch" >/dev/null 2>&1 &'
	script=$'configure\ndelete route bgpdef\ncommit -m "boot test: hand the default to BGP"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	for _ in $(seq 10); do
		dr=$(root_run ip -4 route show default)
		[[ $dr == *"via 10.99.99.2"*"proto bgp"* ]] && break
		sleep 1
	done
	sleep 8 # let the watcher finish
	watch=$(root_run cat /run/outside-watch)
	[[ $dr == *"via 10.99.99.2"*"proto bgp"* && $dr != *"proto sjb"* && $(root_run 'test -f /run/outside-watch && echo yes') == yes && $watch != *gone* ]] &&
		pass "removing a static default hands over to BGP's, outside's address untouched" || fail "static -> bgp default: routes=[$dr] watch=[$watch]"
	# Back to DHCP on outside and no BGP default, for the checks after this.
	root_run "ip netns exec peer vtysh -N peer -c 'conf t' -c 'router bgp 65002' -c 'address-family ipv4 unicast' -c 'no neighbor 10.99.99.1 default-originate'" >/dev/null 2>&1
	script=$'configure\ndelete interface outside address\ncommit -m "boot test: outside back to DHCP"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	for _ in $(seq 20); do
		[[ $(root_run ip -4 route show default) == *"proto dhcp"* ]] && break
		sleep 2
	done
else
	fail "FRR not installed (sjb-packages)"
fi

# --- DHCP server (Kea shipped in the bundle) --------------------------------------
if [[ -n $NEWBUNDLE ]]; then
	for _ in $(seq 90); do
		[[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' kea-dhcp4-server" 2>/dev/null) == installed ]] && break
		sleep 2
	done
fi
if [[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' kea-dhcp4-server" 2>/dev/null) == installed ]]; then
	pass "Kea installed on the appliance ($(root_run "dpkg-query -W -f='\${Version}' kea-dhcp4-server"))"
	# A client namespace on a veth (lab1), with VLAN 30 on it; the firewall
	# serves lab1 in the default VRF and lab1.30 in VRF dv.
	root_run 'set -e
		ip link add lab1 type veth peer name dc0; ip addr add 10.77.0.1/24 dev lab1; ip link set lab1 up
		ip netns add dhcpc; ip link set dc0 netns dhcpc; ip -n dhcpc link set dc0 up; ip -n dhcpc link set lo up
		ip -n dhcpc link add link dc0 name dc0.30 type vlan id 30; ip -n dhcpc link set dc0.30 up
		# The test client listens on a plain UDP socket on an interface with no
		# address (real clients use raw sockets): reverse-path filtering, which
		# the namespace inherits, would drop the server'"'"'s reply.
		ip netns exec dhcpc sh -c "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > \$f; done"
		cat > /root/dhcpc.py' <deploy/appliance/boot-dhcp-client.py
	script=$'configure\nset vrf dv\nset zone dhcplab\nset interface lab1 zone dhcplab address 10.77.0.1/24\nset interface lab1.30 zone dhcplab vrf dv address 10.78.0.1/24\nset dhcp-server lab1 range 10.77.0.100-10.77.0.110 dns 9.9.9.9 domain lab.example lease-time 600 option "66=tftp.lab"\nset dhcp-server lab1.30 range 10.78.0.50-10.78.0.60\nset dhcp-reservation fixed interface lab1 mac 52:54:00:aa:bb:cc address 10.77.0.20\ncommit -m "boot test: dhcp"\nexit\nexit\n'
	out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
	[[ $out == *"committed revision"* ]] && pass "DHCP servers and a reservation configured in configure mode and committed" || fail "dhcp commit: $out"
	dhcpc() { # run the test client on an interface, retrying while Kea starts
		local r
		for _ in 1 2 3 4; do
			r=$(root_run "ip netns exec dhcpc python3 /root/dhcpc.py $1" 2>/dev/null) && { echo "$r"; return; }
			sleep 3
		done
		echo "$r"
	}
	c1=$(dhcpc dc0)
	[[ $c1 == *'"address": "10.77.0.1'[01]* && $c1 == *'"router": ["10.77.0.1"]'* && $c1 == *'"dns": ["9.9.9.9"]'* &&
		$c1 == *'"domain": "lab.example"'* && $c1 == *'"lease": 600'* && $c1 == *'"tftp": "tftp.lab"'* ]] &&
		pass "a client gets a pool address with gateway, DNS, domain, lease time and option 66" ||
		fail "dhcp pool: $c1; rp_filter: $(root_run 'ip netns exec dhcpc cat /proc/sys/net/ipv4/conf/all/rp_filter /proc/sys/net/ipv4/conf/dc0/rp_filter' | xargs); kea: $(root_run 'systemctl is-active kea-dhcp4-server; journalctl -u kea-dhcp4-server --no-pager -n 15 | grep -E "ERROR|WARN|Failed|failed"' 2>&1)"
	root_run 'ip -n dhcpc link set dc0 address 52:54:00:aa:bb:cc'
	c2=$(dhcpc dc0)
	[[ $c2 == *'"address": "10.77.0.20"'* ]] && pass "the reserved MAC gets its reserved address" || fail "dhcp reservation: $c2"
	c3=$(dhcpc dc0.30)
	[[ $c3 == *'"address": "10.78.0.5'* && $c3 == *'"router": ["10.78.0.1"]'* && $c3 == *'"dns": ["10.98.0.3"]'* ]] &&
		pass "a client on a VLAN in a VRF gets its own pool, with the firewall's DNS by default" ||
		fail "dhcp vlan/vrf: $c3; kea: $(root_run 'ip -br addr show lab1.30; journalctl -u kea-dhcp4-server --no-pager -n 60 | grep -E "SOCKET|IFACE|lab1|ERROR|WARN" | cut -c1-260 | tail -12' 2>&1)"
	sd=$(cli_run show dhcp); sl=$(cli_run show dhcp leases)
	[[ $sd == *"running"* && $sd == *lab1.30*10.78.0.0/24* && $sl == *10.77.0.20*52:54:00:aa:bb:cc*fixed* && $sl == *lab1.30*10.78.0.5* ]] &&
		pass "show dhcp and show dhcp leases list the servers and leases" || fail "show dhcp: $sd / $sl"
	ul=$(ui "$UI/ui/api/dhcp/leases")
	[[ $ul == *'"address":"10.77.0.20"'* && $ul == *'"reserved":"fixed"'* ]] && pass "web UI DHCP leases" || fail "ui dhcp leases: ${ul:0:300}"
	inp=$(root_run nft list chain inet ngfw input)
	[[ $inp == *'iifname "lab1" udp dport 67 accept'* && $inp == *'meta sdifname "lab1.30" udp dport 67 accept'* ]] &&
		pass "input chain accepts DHCP on the served interfaces only" || fail "dhcp input: $inp"
	lg=$(cli_run show log system 200 DHCP4_LEASE_ALLOC)
	[[ $lg == *dhcp*10.77.0.20* ]] && pass "Kea's lease messages are in show log system" || fail "dhcp log: ${lg:0:300}"
	# Removing the servers stops Kea; the leases file stays.
	script=$'configure\ndelete dhcp-reservation fixed\ndelete dhcp-server lab1\ndelete dhcp-server lab1.30\ndelete interface lab1.30\ndelete interface lab1\ndelete zone dhcplab\ndelete vrf dv\ncommit -m "boot test: no dhcp"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	for _ in $(seq 10); do
		ka=$(root_run systemctl is-active kea-dhcp4-server)
		[[ $ka != active ]] && break
		sleep 1
	done
	[[ $ka != active && $(root_run systemctl is-enabled kea-dhcp4-server) == disabled ]] &&
		pass "with no DHCP servers Kea is stopped and disabled" || fail "kea after removal: $ka"
	root_run 'ip netns del dhcpc; ip link del lab1' >/dev/null 2>&1
else
	fail "Kea not installed (sjb-packages)"
fi

# --- App Identification (appidd + nDPI shipped in the bundle) ----------------------------------
if [[ -n $NEWBUNDLE ]]; then
	for _ in $(seq 60); do
		[[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' libnetfilter-queue1" 2>/dev/null) == installed &&
			$(root_run systemctl is-active appidd) == active ]] && break
		sleep 3
	done
fi
ach=$(root_run nft list chain inet ngfw appid 2>&1)
[[ $(root_run systemctl is-active appidd) == active && $ach == *"queue flags bypass,fanout to 0-1"* ]] &&
	pass "App Identification running: appidd active, the ruleset queues new connections to it" || fail "appidd: $(root_run 'systemctl status appidd --no-pager -n 5' 2>&1 | tail -5) / $ach"
# A client and a server on either side of the firewall, with a logged rule.
root_run 'set -e
	ip link add ap1 type veth peer name apc0; ip addr add 10.81.0.1/24 dev ap1; ip link set ap1 up
	ip link add ap2 type veth peer name aps0; ip addr add 10.82.0.1/24 dev ap2; ip link set ap2 up
	ip netns add apc; ip link set apc0 netns apc; ip -n apc addr add 10.81.0.2/24 dev apc0; ip -n apc link set apc0 up; ip -n apc route add default via 10.81.0.1
	ip netns add aps; ip link set aps0 netns aps; ip -n aps addr add 10.82.0.2/24 dev aps0; ip -n aps link set aps0 up; ip -n aps route add default via 10.82.0.1
	ip -n apc link set lo up; ip -n aps link set lo up
	cat > /root/appid-traffic.py' <deploy/appliance/boot-appid-traffic.py
root_run 'nohup ip netns exec aps python3 /root/appid-traffic.py server >/dev/null 2>&1 &'
script=$'configure\nset zone appcli\nset zone appsrv\nset interface ap1 zone appcli address 10.81.0.1/24\nset interface ap2 zone appsrv address 10.82.0.1/24\nset rule app-test from appcli to appsrv action allow log yes\ncommit -m "boot test: app-identification"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
[[ $out == *"committed revision"* ]] || fail "app-identification commit: $out"
sleep 1
tr=$(root_run 'ip netns exec apc python3 /root/appid-traffic.py client 10.82.0.2')
# Close the connections now (instead of waiting out TIME_WAIT) so their ends are logged.
sleep 1; root_run 'conntrack -D --orig-src 10.81.0.2 >/dev/null 2>&1; true'; sleep 12
sa=$(cli_run show app)
[[ $tr == *"200 OK"* && $sa == *YouTube* && $sa == *NetFlix* && $sa == *SSH* && $sa == *DNS* ]] &&
	pass "App Identification identifies YouTube (TLS server name), Netflix (HTTP host), SSH and DNS (show app)" || fail "show app: $tr / $sa"
lt=$(cli_run show log traffic app-test columns type,rule,app,bytes)
[[ $lt == *end*app-test*YouTube* && $lt == *end*app-test*NetFlix* ]] &&
	pass "traffic log has end entries with the application and bytes" || fail "app log: $lt"
ua=$(ui "$UI/ui/api/apps"); cat=$(cli_run show app catalog youtube)
[[ $ua == *'"name":"YouTube"'* && $ua == *'"running":true'* && $cat == *YouTube*Media* ]] &&
	pass "web UI apps view and the catalog" || fail "ui apps: ${ua:0:300} / $cat"
# App policy (step 2): deny YouTube above the allow rule; the rest flows.
# The deny goes through an application group holding a category: YouTube is
# in nDPI's Media category, Netflix in Video, so Netflix still flows.
script=$'configure\nset application-group streaming member [ category:media ]\nset rule no-tube from appcli to appsrv application [ streaming ] action deny log yes\nmove rule no-tube top\ncommit -m "boot test: deny streaming (category:media)"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
[[ $out == *"committed revision"* ]] || fail "app policy commit: $out"
tr=$(root_run 'ip netns exec apc python3 /root/appid-traffic.py client 10.82.0.2'); sleep 2
nt=$(cli_run show log traffic where rule = no-tube)
[[ $tr == *"'http': 'HTTP/1.1 200 OK'"* && $tr == *"'ssh': 'SSH-2.0"* && $tr == *"'dns': 'answered'"* && $nt == *no-tube*deny*10.81.0.2*443* ]] &&
	pass "app policy: a group with category:media denies YouTube once identified (logged); Netflix, SSH, DNS flow" || fail "deny youtube: $tr / $nt"
# Allow only SSH and DNS: HTTP is cut off when App Identification names it (app shift).
script=$'configure\ndelete rule no-tube\ndelete application-group streaming\nset rule app-test application [ ssh dns ]\ncommit -m "boot test: ssh and dns only"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
tr=$(root_run 'ip netns exec apc python3 /root/appid-traffic.py client 10.82.0.2')
[[ $tr == *"'http': 'timed out'"* && $tr == *"'ssh': 'SSH-2.0"* && $tr == *"'dns': 'answered'"* ]] &&
	pass "app policy: only SSH and DNS allowed, HTTP cut off once identified" || fail "ssh-only: $tr"
script=$'configure\ndelete rule app-test application\ncommit -m "boot test: any app again"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
# Fail-open: with appidd stopped, traffic still flows.
root_run systemctl stop appidd
tr=$(root_run 'ip netns exec apc python3 /root/appid-traffic.py client 10.82.0.2')
[[ $tr == *"'http': 'HTTP/1.1 200 OK'"* && $tr == *"'ssh': 'SSH-2.0"* && $tr == *"'dns': 'answered'"* ]] &&
	pass "traffic flows with appidd stopped (queue bypass)" || fail "fail-open: $tr"
root_run systemctl start appidd
script=$'configure\nset system app-identification off\ncommit -m "boot test: app-identification off"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
off=$(root_run nft list chain inet ngfw appid 2>&1)
[[ $off == *"No such file or directory"* || $off == *"does not exist"* ]] && pass "set system app-identification off removes the queue chain" || fail "app-identification off: $off"
script=$'configure\ndelete system app-identification\ndelete rule app-test\ndelete interface ap1\ndelete interface ap2\ndelete zone appcli\ndelete zone appsrv\ncommit -m "boot test: app-identification cleanup"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
root_run 'ip netns pids aps | xargs -r kill; ip netns del apc; ip netns del aps; ip link del ap1; ip link del ap2' >/dev/null 2>&1

# --- IPS (Suricata shipped in the bundle, ET Open downloaded) -----------------------
if [[ -n $NEWBUNDLE ]]; then
	for _ in $(seq 90); do
		[[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' suricata" 2>/dev/null) == installed ]] && break
		sleep 2
	done
fi
if [[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' suricata" 2>/dev/null) == installed ]]; then
	pass "Suricata installed on the appliance ($(root_run "dpkg-query -W -f='\${Version}' suricata")), Debian's unit masked ($(root_run systemctl is-enabled suricata 2>&1))"
	# Client (two addresses) and server on either side of the firewall.
	root_run 'set -e
		ip link add ip1 type veth peer name ipc0; ip addr add 10.83.0.1/24 dev ip1; ip link set ip1 up
		ip link add ip2 type veth peer name ips0; ip addr add 10.84.0.1/24 dev ip2; ip link set ip2 up
		ip netns add ipc; ip link set ipc0 netns ipc; ip -n ipc addr add 10.83.0.2/24 dev ipc0; ip -n ipc addr add 10.83.0.3/24 dev ipc0; ip -n ipc addr add 10.83.0.4/24 dev ipc0
		ip -n ipc link set ipc0 up; ip -n ipc link set lo up; ip -n ipc route add default via 10.83.0.1
		ip netns add ipsrv; ip link set ips0 netns ipsrv; ip -n ipsrv addr add 10.84.0.2/24 dev ips0
		ip -n ipsrv link set ips0 up; ip -n ipsrv link set lo up; ip -n ipsrv route add default via 10.84.0.1
		cat > /root/ips-traffic.py' <deploy/appliance/boot-ips-traffic.py
	root_run 'nohup ip netns exec ipsrv python3 /root/ips-traffic.py server >/dev/null 2>&1 &'
	# 10.83.0.3 gets a strict profile (minor blocked, informational alerted);
	# the rest of the zone the built-in default.
	script=$'configure\nset zone ipscli\nset zone ipssrv\nset interface ip1 zone ipscli address 10.83.0.1/24\nset interface ip2 zone ipssrv address 10.84.0.1/24\nset address strict-host cidr 10.83.0.3\nset ips-profile strict minor block informational alert\nset rule ips-strict from ipscli to ipssrv source strict-host action allow ips-profile strict\nset rule ips-test from ipscli to ipssrv action allow ips-profile default\ncommit -m "boot test: ips"\nexit\nexit\n'
	out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
	[[ $out == *"committed revision"* ]] || fail "ips commit: $out"
	# ngfwd downloads ET Open in the background and starts sjb-ips; Suricata
	# then loads the signatures (a minute or more).
	# Wait until the engine itself reports the ET set loaded (show ips asks
	# Suricata), not just the rules file written.
	for _ in $(seq 150); do
		si=$(cli_run show ips)
		n=$(grep -oE 'running, [0-9]+ signatures loaded' <<<"$si" | grep -oE '[0-9]+')
		[[ ${n:-0} -gt 10000 ]] && break
		sleep 4
	done
	[[ $(root_run systemctl is-active sjb-ips) == active && ${n:-0} -gt 10000 && $si == *"ET Open"* && $si == *"ips-test (default)"* ]] &&
		pass "IPS running: sjb-ips active, $n ET Open signatures loaded in the engine (show ips)" ||
		fail "ips engine: $si / $(root_run 'journalctl -u sjb-ips -b --no-pager -n 8 -o cat' 2>&1)"
	ich=$(root_run nft list ruleset)
	[[ $ich == *"chain ips {"*"queue flags bypass,fanout to 2-3"* && $ich == *"chain ips_enforce {"* ]] &&
		pass "the ruleset queues the IPS rules' traffic to Suricata and enforces the profiles" || fail "ips chains: $(grep -A3 'chain ips' <<<"$ich")"
	get() { root_run "ip netns exec ipc python3 /root/ips-traffic.py client 10.84.0.2 $1 $2"; }
	r=$(printf '%s ' "$(get 10.83.0.2 plain)" "$(get 10.83.0.2 SJB-IPS-TEST-CRITICAL)" "$(get 10.83.0.2 SJB-IPS-TEST-MAJOR)" \
		"$(get 10.83.0.2 SJB-IPS-TEST-MINOR)" "$(get 10.83.0.2 SJB-IPS-TEST-INFO)")
	[[ $r == "200 blocked blocked 200 200 " ]] &&
		pass "default profile: critical and major blocked, minor and informational pass" || fail "default profile: $r"
	r=$(printf '%s ' "$(get 10.83.0.3 SJB-IPS-TEST-MINOR)" "$(get 10.83.0.3 uid)")
	[[ $r == "blocked 200 " ]] && pass "strict profile: minor blocked; an ET Open informational signature (uid=0 response) alerted" || fail "strict profile: $r"
	# Alerts reach the log a moment after the traffic (Suricata, then ngfwd's
	# conntrack lookup): wait for the last one.
	for _ in $(seq 15); do
		lt=$(cli_run show log threat 50 columns rule,action,severity,sid,src)
		[[ $lt == *2100498* ]] && break
		sleep 2
	done
	[[ $lt == *ips-test*block*critical*9900001*10.83.0.2* && $lt == *ips-test*block*major*9900002* && $lt == *ips-test*alert*minor*9900003* &&
		$lt == *ips-strict*block*minor*9900003*10.83.0.3* && $lt == *ips-strict*alert*informational*2100498* && $lt != *9900004*10.83.0.2* ]] &&
		pass "threat log: rule, action and severity per match; the default profile's informational matches not logged" || fail "threat log: $lt"
	ut=$(ui "$UI/ui/api/logs/threat?q=$(python3 -c 'import urllib.parse;print(urllib.parse.quote("severity = critical"))')")
	[[ $ut == *'"sid":9900001'* && $ut != *'"severity":"major"'* ]] && pass "web UI threat log with a query" || fail "ui threat log: ${ut:0:300}"
	si=$(cli_run show ips)
	[[ $si == *"inspection"*"INSPECTING"* ]] && pass "show ips: inspection state INSPECTING (the engine is bound to its queue)" || fail "inspection state: $si"

	# App Identification and the IPS together: 10.83.0.4 may only use HTTP
	# (application rule with the default profile); anything else from it is
	# denied. Packets that pass before App Identification names the
	# connection carry the rule's tag, so the IPS inspects them too, and the
	# pending allowance is bounded.
	script=$'configure\nset address app-host cidr 10.83.0.4\nset rule app-ips from ipscli to ipssrv source app-host application [ http ] action allow ips-profile default\nset rule app-host-rest from ipscli to ipssrv source app-host action deny\nmove rule app-ips top\nmove rule app-host-rest after app-ips\ncommit -m "boot test: app + ips"\nexit\nexit\n'
	out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
	[[ $out == *"committed revision"* ]] || fail "app + ips commit: $out"
	sleep 2
	raw() { root_run "ip netns exec ipc python3 /root/ips-traffic.py raw 10.84.0.2 10.83.0.4 $1"; }
	stream() { root_run "ip netns exec ipc python3 /root/ips-traffic.py stream 10.84.0.2 10.83.0.4 $1"; }
	r=$(printf '%s ' "$(get 10.83.0.4 plain)" "$(get 10.83.0.4 SJB-IPS-TEST-CRITICAL)" "$(raw hello)" "$(raw SJB-IPS-TEST-CRITICAL)")
	[[ $r == "200 blocked passed blocked " ]] &&
		pass "application rule + IPS: HTTP allowed, a signature in the first request blocked, and a signature in the first bytes, before the application is known, blocked too" ||
		fail "app + ips: $r (want: 200 blocked passed blocked)"
	# Classifier failure: with appidd stopped nothing is classified (its
	# queue is bypassed). The application rule still lets an unidentified
	# connection through for at most 40 packets, then the deny below it decides.
	root_run systemctl stop appidd
	sleep 2
	sa=$(cli_run show app)
	[[ $sa == *"Traffic: UNAVAILABLE"*"at most 40 packets"* ]] && pass "appidd stopped: show app says App Identification is unavailable and what that means" || fail "show app with appidd stopped: $sa"
	n=$(stream 100)
	[[ $n =~ ^[0-9]+$ && $n -gt 0 && $n -lt 40 ]] &&
		pass "appidd stopped: an unidentified connection on the application rule is cut after $n echoes (bounded, not unrestricted)" ||
		fail "appidd stopped: $n of 100 echoes came back (want a bounded cut-off)"
	r=$(raw SJB-IPS-TEST-CRITICAL)
	[[ $r == blocked ]] && pass "appidd stopped: the IPS still inspects the application rule's pending traffic" || fail "appidd stopped, signature: $r"
	root_run systemctl start appidd
	for _ in $(seq 15); do [[ $(cli_run show app) == *"Traffic: CLASSIFYING"* ]] && break; sleep 2; done
	[[ $(cli_run show app) == *"Traffic: CLASSIFYING"* ]] && pass "appidd back: show app says CLASSIFYING" || fail "appidd restart: $(cli_run show app | head -3)"
	script=$'configure\ndelete rule app-ips\ndelete rule app-host-rest\ndelete address app-host\ncommit -m "boot test: app + ips cleanup"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	# (The test VM's emulated network sometimes times out DNS lookups.)
	for _ in 1 2 3 4 5 6; do
		up=$(cli_run request ips update 2>&1)
		[[ $up == *"IPS signatures updated"* ]] && break
		sleep 20
	done
	[[ $up == *"IPS signatures updated"* ]] && pass "request ips update downloads the signatures again" || fail "ips update: $up"
	# Let the engine finish loading what the update brought (stopping it in
	# the middle of a reload waits for the reload).
	for _ in $(seq 60); do
		[[ $(cli_run show ips) == *"signatures loaded"* ]] && break
		sleep 3
	done
	# Fail-open, then ngfwd brings the engine back.
	# (While Suricata shuts down it still holds the queue; bypass applies once
	# it has exited.)
	root_run systemctl stop sjb-ips
	# A stop during a rule reload waits for the reload to finish, and the
	# engine holds its queue until it exits: keep trying for up to 30 s.
	for _ in $(seq 10); do
		r=$(get 10.83.0.2 SJB-IPS-TEST-CRITICAL)
		[[ $r == 200 ]] && break
		sleep 3
	done
	for _ in $(seq 20); do [[ $(root_run systemctl is-active sjb-ips) == active ]] && break; sleep 2; done
	[[ $r == 200 && $(root_run systemctl is-active sjb-ips) == active ]] &&
		pass "traffic flows with Suricata stopped (queue bypass); ngfwd restarts it" ||
		fail "ips fail-open: $r / $(root_run systemctl is-active sjb-ips) / $(root_run 'journalctl -u sjb-ips -b --no-pager -o short-monotonic -n 14 | cut -c1-160' 2>&1)"
	script=$'configure\nset system ips off\ncommit -m "boot test: ips off"\nexit\nexit\n'
	out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
	for _ in $(seq 10); do [[ $(root_run systemctl is-active sjb-ips) != active ]] && break; sleep 1; done
	[[ $out == *"IPS is off"* && $(root_run nft list ruleset) != *"chain ips"* && $(root_run systemctl is-active sjb-ips) != active ]] &&
		pass "set system ips off: profiles skipped with a warning, chains removed, engine stopped" || fail "ips off: $out"
	script=$'configure\ndelete system ips\ndelete rule ips-strict\ndelete rule ips-test\ndelete ips-profile strict\ndelete address strict-host\ndelete interface ip1\ndelete interface ip2\ndelete zone ipscli\ndelete zone ipssrv\ncommit -m "boot test: ips cleanup"\nexit\nexit\n'
	retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
	root_run 'ip netns pids ipsrv | xargs -r kill; ip netns del ipc; ip netns del ipsrv; ip link del ip1; ip link del ip2' >/dev/null 2>&1
else
	fail "Suricata not installed (sjb-packages): $(root_run 'journalctl -u sjb-packages -b --no-pager -o cat | grep -iE "error|fail|support|suricata" | tail -6' 2>&1)"
fi

# --- TLS decryption (tlsd) --------------------------------------------------------
# A client and an HTTPS server on either side of the firewall, with a test
# "public" root that tlsd trusts for this run only (a runtime drop-in). The
# server answers with the address it saw: the firewall's when tlsd carried
# the connection, the client's when it went straight through.
dsec=$(root_run 'id -u sjb-tls; stat -c %a /usr/local/sbin/tlsd /usr/local/sbin/sjb-decrypt-net; systemctl cat sjb-tlsd | grep -c CapabilityBoundingSet=CAP_NET_ADMIN; test -s /etc/ssl/certs/ca-certificates.crt && echo roots; stat -c "%U:%G %a" /etc/ngfw/decryption /etc/ngfw' 2>&1)
[[ $dsec =~ ^[0-9]+$'\n'755$'\n'755$'\n'1$'\n'roots$'\n''root:sjb-tls 750'$'\n''root:root 700'$ ]] &&
	pass "decryption installed: tlsd and sjb-decrypt-net, user sjb-tls, a capability-limited sjb-tlsd unit, Debian's trusted roots; /etc/ngfw stays root-only" ||
	fail "decryption install: $dsec"
root_run 'set -e
	d=/etc/ssl/sjb-boottest; mkdir -p $d; cd $d
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout testca.key -subj "/CN=Boot Test Public Root" \
		-days 2 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -out testca.crt 2>/dev/null
	for n in shop.example www.bank.example app.example bad.example; do
		openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $n.key -subj "/CN=$n" -out $n.csr 2>/dev/null
		printf "subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n" $n >$n.ext
		if [ $n = bad.example ]; then openssl x509 -req -in $n.csr -signkey $n.key -days 2 -extfile $n.ext -out $n.crt 2>/dev/null
		else openssl x509 -req -in $n.csr -CA testca.crt -CAkey testca.key -CAcreateserial -days 2 -extfile $n.ext -out $n.crt 2>/dev/null; fi
	done
	chmod 644 *.crt
	mkdir -p /run/systemd/system/sjb-tlsd.service.d
	printf "[Service]\nEnvironment=SSL_CERT_FILE=%s/testca.crt\n" $d >/run/systemd/system/sjb-tlsd.service.d/boot-test.conf
	systemctl daemon-reload
	ip link add dc1 type veth peer name dcc0; ip addr add 10.85.0.1/24 dev dc1; ip link set dc1 up
	ip link add dc2 type veth peer name dcs0; ip addr add 10.86.0.1/24 dev dc2; ip link set dc2 up
	ip netns add dcc; ip link set dcc0 netns dcc; ip -n dcc addr add 10.85.0.2/24 dev dcc0
	ip -n dcc link set dcc0 up; ip -n dcc link set lo up; ip -n dcc route add default via 10.85.0.1
	ip netns add dcs; ip link set dcs0 netns dcs; ip -n dcs addr add 10.86.0.2/24 dev dcs0
	ip -n dcs link set dcs0 up; ip -n dcs link set lo up; ip -n dcs route add default via 10.86.0.1
	cat > /root/decrypt-traffic.py' <deploy/appliance/boot-decrypt-traffic.py
root_run 'nohup ip netns exec dcs python3 /root/decrypt-traffic.py server /etc/ssl/sjb-boottest >/dev/null 2>&1 &'
dget() { root_run "ip netns exec dcc python3 /root/decrypt-traffic.py client $1 10.86.0.2 $2 $3"; }
script=$'configure\nset zone dcli\nset zone dsrv\nset interface dc1 zone dcli address 10.85.0.1/24\nset interface dc2 zone dsrv address 10.86.0.1/24\nset service tls protocol tcp ports 443\nset rule dec-out from dcli to dsrv service tls action allow ips-profile default\nset decryption-exclusion boot-bank domain [ bank.example ]\nset decryption-rule dec from dcli to dsrv service tls action decrypt\ncommit -m "boot test: decryption"\nexit\nexit\n'
out=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" 2>&1)
[[ $out == *"committed revision"* && $out == *"no decryption CA yet"* ]] && pass "decryption rule committed; the commit warns that there is no CA yet" || fail "decryption commit: $out"
out=$(cli_run request decryption ca generate)
ca=$(root_run 'stat -c "%U %a" /etc/ngfw/decryption/ca.key; stat -c "%U:%G %a" /etc/ngfw/decryption')
[[ $out == *"new decryption CA"* && $ca == "sjb-tls 600"$'\n'"root:sjb-tls 750" ]] &&
	pass "request decryption ca generate: key readable by tlsd's user only (ca.key sjb-tls 600, directory root:sjb-tls 750)" || fail "CA generate: $out / $ca"
cli_run show decryption ca | sed -n '/BEGIN CERT/,/END CERT/p' | root_run 'cat > /root/sjbca.pem'
[[ $(root_run 'grep -c "BEGIN CERTIFICATE" /root/sjbca.pem') == 1 ]] && pass "show decryption ca prints the certificate for clients" || fail "show decryption ca"
uc=$(ui "$UI/ui/api/decryption/ca.crt")
[[ $uc == "-----BEGIN CERTIFICATE-----"* && $uc != *PRIVATE* ]] && pass "web UI: CA certificate download (no key)" || fail "ui CA download: ${uc:0:80}"
for _ in $(seq 20); do
	sd=$(cli_run show decryption)
	[[ $sd == *OBSERVING* || $sd == *DECRYPTING* ]] && break
	sleep 2
done
[[ $(root_run systemctl is-active sjb-tlsd) == active && ( $sd == *OBSERVING* || $sd == *DECRYPTING* ) ]] &&
	pass "ngfwd started sjb-tlsd; show decryption: $(grep -oE 'OBSERVING|DECRYPTING' <<<"$sd")" || fail "tlsd start: $sd / $(root_run 'journalctl -u sjb-tlsd -b --no-pager -n 10 -o cat' 2>&1)"
if [[ $sd == *OBSERVING* ]]; then
	r=$(dget shop.example /etc/ssl/sjb-boottest/testca.crt /observed)
	[[ $r == *"seen from 10.86.0.1 path /observed"*"issuer: Boot Test Public Root"* ]] &&
		pass "observe: the connection went through tlsd (the server saw the firewall) with the server's own certificate" || fail "observe: $r"
	for _ in $(seq 5); do ld=$(cli_run show log decryption 5 columns decision,server_name,src); [[ $ld == *would-decrypt*shop.example* ]] && break; sleep 2; done
	[[ $ld == *would-decrypt*shop.example*10.85.0.2* ]] && pass "show log decryption: would-decrypt shop.example" || fail "decryption log: $ld"
else
	r=$(dget shop.example /root/sjbca.pem /hello)
	[[ $r == *"seen from 10.86.0.1 path /hello"*"issuer: SJB-OS Decryption CA"* ]] &&
		pass "decrypted: the client gets a certificate from the SJB-OS CA; the server's was checked against the trusted roots" || fail "decrypt: $r"
	r=$(dget www.bank.example /etc/ssl/sjb-boottest/testca.crt /)
	[[ $r == *"issuer: Boot Test Public Root"* ]] && pass "excluded name: not decrypted, the server's own certificate" || fail "exclusion: $r"
	r=$(dget app.example /etc/ssl/sjb-boottest/testca.crt /); r2=$(dget app.example /etc/ssl/sjb-boottest/testca.crt /)
	[[ $r == ERROR* && $r2 == *"issuer: Boot Test Public Root"* && $(cli_run show decryption learned) == *app.example* ]] &&
		pass "a client that rejects the firewall's certificate is learned and passed through after" || fail "pinned: $r / $r2"
	r=$(dget bad.example /root/sjbca.pem /)
	[[ $r == ERROR* ]] && pass "a self-signed server certificate is shown as untrusted: the client refuses it" || fail "bad cert: $r"
	# The IPS sees inside HTTPS: wait for the engine (restarted by this
	# commit), then a signature in a decrypted request is blocked.
	for _ in $(seq 120); do [[ $(cli_run show ips) == *INSPECTING* ]] && break; sleep 3; done
	r=$(dget shop.example /root/sjbca.pem /SJB-IPS-TEST-CRITICAL)
	for _ in $(seq 10); do lt=$(cli_run show log threat 10 columns rule,action,sid); [[ $lt == *dec-out*block*9900001* ]] && break; sleep 2; done
	[[ $r == blocked || $r == ERROR* ]] && [[ $lt == *dec-out*block*9900001* ]] &&
		pass "the IPS blocks a signature inside an HTTPS request (threat log: dec-out block 9900001)" || fail "IPS in HTTPS: $r / $lt"
	for _ in $(seq 5); do ld=$(cli_run show log decryption 20 columns decision,server_name); [[ $ld == *decrypted*shop.example* && $ld == *excluded*www.bank.example* && $ld == *learned*app.example* ]] && break; sleep 2; done
	[[ $ld == *decrypted*shop.example* && $ld == *excluded*www.bank.example* && $ld == *learned*app.example* ]] &&
		pass "show log decryption: decrypted, excluded and learned entries" || fail "decryption log: $ld"
fi
uj=$(ui "$UI/ui/api/decryption")
[[ $uj == *'"state":"'* && $uj == *'"fingerprint":"'* && $uj != *PRIVATE* ]] && pass "web UI: decryption status" || fail "ui decryption: ${uj:0:200}"
# Fail-open: tlsd stopped, connections take the normal path; ngfwd starts it again.
root_run systemctl stop sjb-tlsd
for _ in $(seq 10); do r=$(dget shop.example /etc/ssl/sjb-boottest/testca.crt /direct); [[ $r == *"seen from 10.85.0.2"* ]] && break; sleep 1; done
[[ $r == *"seen from 10.85.0.2 path /direct"* ]] && pass "tlsd stopped: traffic passes undecrypted, straight through (fail-open)" || fail "fail-open: $r"
for _ in $(seq 20); do [[ $(root_run systemctl is-active sjb-tlsd) == active ]] && break; sleep 2; done
[[ $(root_run systemctl is-active sjb-tlsd) == active ]] && pass "ngfwd starts sjb-tlsd again" || fail "tlsd restart"
script=$'configure\nset system decryption off\ncommit -m "boot test: decryption off"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
for _ in $(seq 10); do [[ $(root_run systemctl is-active sjb-tlsd) != active ]] && break; sleep 1; done
[[ $(root_run systemctl is-active sjb-tlsd) != active && $(root_run 'nft list ruleset') != *"chain decrypt "* && $(root_run 'ip netns list') != *sjbd-c* ]] &&
	pass "set system decryption off: tlsd stopped, the hand-over chain and the loop removed" || fail "decryption off"
script=$'configure\ndelete system decryption\ndelete decryption-rule dec\ndelete decryption-exclusion boot-bank\ndelete rule dec-out\ndelete service tls\ndelete interface dc1\ndelete interface dc2\ndelete zone dcli\ndelete zone dsrv\ncommit -m "boot test: decryption cleanup"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
root_run 'ip netns pids dcs | xargs -r kill; ip netns del dcc; ip netns del dcs; ip link del dc1; ip link del dc2; rm -rf /run/systemd/system/sjb-tlsd.service.d; systemctl daemon-reload' >/dev/null 2>&1

# --- hostname: a commit renames the appliance ------------------------------------
oldhn=$(root_run hostname)
script=$'configure\nset system hostname bt-renamed\ncommit -m "boot test: rename"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
hn=$(root_run 'hostname; cat /etc/hostname; grep "^127.0.1.1" /etc/hosts')
pr=$(retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<$'exit\n' 2>&1)
[[ $hn == $'bt-renamed\nbt-renamed\n127.0.1.1 bt-renamed' && $pr == *"@bt-renamed>"* ]] &&
	pass "set system hostname renames the appliance: hostname, /etc/hostname, /etc/hosts and the CLI prompt" || fail "rename: $hn / prompt: ${pr:0:200}"
script=$'configure\nset system hostname '"$oldhn"$'\ncommit -m "boot test: rename back"\nexit\nexit\n'
retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no "$ADMIN@127.0.0.1" <<<"$script" >/dev/null 2>&1
[[ $(root_run hostname) == "$oldhn" ]] && pass "renamed back to $oldhn" || fail "rename back: $(root_run hostname)"

# --- dashboard statistics (a sample a minute) ------------------------------------
# The App Identification and IPS traffic above was sampled; wait for the minute in
# progress, then check the hour's report and the CLI.
sleep 65
sj=$(ui "$UI/ui/api/stats?window=1h")
[[ $sj == *'"samples":'[1-9]* && $sj == *'"name":"YouTube"'* && $sj == *'"name":"10.81.0.2"'* && $sj == *'"sid":9900001'* &&
	$sj == *'"in_bytes":'[1-9]* ]] &&
	pass "dashboard statistics: throughput, applications (YouTube), hosts and IPS matches in the last hour" ||
	fail "stats: $(python3 -c 'import json,sys
j=json.load(sys.stdin)
print("samples", j.get("samples"), "| apps", [a.get("name") for a in j.get("apps") or []], "| hosts", [h.get("name") for h in j.get("hosts") or []],
      "| sids", [x.get("sid") for x in (j.get("threats") or {}).get("top") or []], "| keys", sorted(j))' <<<"$sj" 2>&1) / samples on disk: $(root_run 'wc -l < /var/lib/ngfw/stats/samples.jsonl; head -c 120 /var/lib/ngfw/stats/samples.jsonl; echo; date +%s')"
ss=$(cli_run show statistics 1h)
[[ $ss == *YouTube* && $ss == *"10.81.0.2"* && $ss == *9900001* ]] && pass "show statistics prints the same" || fail "show statistics: ${ss:0:300}"
n1=$(grep -o '"samples":[0-9]*' <<<"$sj" | grep -o '[0-9]*$')
root_run systemctl restart ngfwd
sleep 3
login=$(curl -sk -c "$JAR" -H 'Content-Type: application/json' -d "{\"user\":\"$ADMIN\",\"password\":\"$PW\"}" "$UI/ui/api/login")
CSRF=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf",""))' <<<"$login" 2>/dev/null)
n2=$(ui "$UI/ui/api/stats?window=1h" | grep -o '"samples":[0-9]*' | grep -o '[0-9]*$')
[[ ${n2:-0} -ge ${n1:-1} ]] && pass "statistics survive an ngfwd restart ($n2 samples)" || fail "after restart: $n1 -> $n2 samples"

REV_BEFORE=$(root_run fwctl status | grep -o '"running_revision": [0-9]*' | grep -o '[0-9]*$')

# --- upgrades ---------------------------------------------------------------------
# Test bundles are built from this build's binaries and overlay with newer
# versions, and signed with the real release key the image trusts.
bundle() { # version out [broken]
	local st=$WORK/stage-$1
	mkdir -p "$st/usr/local/sbin" "$st/etc"
	cp -R "$SRC/deploy/appliance/rootfs/." "$st/"
	find "$st" -name .DS_Store -delete
	install -m 755 "$SRC/build/appliance/bin/ngfwd" "$SRC/build/appliance/bin/fwctl" "$st/usr/local/sbin/"
	chmod 755 "$st"/usr/local/sbin/* "$st/etc/update-motd.d/10-sjb"
	[[ ${3:-} == broken ]] && printf '#!/bin/sh\necho "not a firewall daemon" >&2\nexit 1\n' >"$st/usr/local/sbin/ngfwd"
	echo "$1" >"$st/etc/ngfw-version"
	(cd "$SRC" && go run ./cmd/sjbpkg build -root "$st" -version "$1" -key "$SIGNING_KEY" -o "$2") >/dev/null
}
upstatus() { root_run fwctl upgrade status -json; }
wait_upgrade() {
	for _ in $(seq 90); do
		upstatus | grep -q '"in_progress": false' && return 0
		sleep 2
	done
	return 1
}
if [[ -f $SIGNING_KEY ]] && command -v go >/dev/null; then
	ORIG=$(root_run cat /etc/ngfw-version)
	IFS=. read -r MAJ MIN PAT <<<"${ORIG%%[-+]*}"
	V1=$MAJ.$MIN.$((PAT + 1))-boottest
	V2=$MAJ.$MIN.$((PAT + 2))-boottest
	bundle "$V1" "$WORK/good.upgrade"
	bundle "$V2" "$WORK/broken.upgrade" broken

	up=$(curl -sk -b "$JAR" -H "X-SJB-CSRF: $CSRF" -H 'Content-Type: application/octet-stream' \
		--data-binary @"$WORK/good.upgrade" "$UI/ui/api/upgrade")
	[[ $up == *"\"version\":\"$V1\""* ]] && pass "web UI accepts and verifies a signed bundle" || fail "upload: $up"
	tampered=$WORK/tampered.upgrade
	python3 - "$WORK/good.upgrade" "$tampered" <<'PY'
import sys; b=bytearray(open(sys.argv[1],'rb').read()); b[2000]^=1; open(sys.argv[2],'wb').write(b)
PY
	bad=$(curl -sk -b "$JAR" -H "X-SJB-CSRF: $CSRF" --data-binary @"$tampered" "$UI/ui/api/upgrade")
	[[ $bad == *"invalid upgrade bundle"* ]] && pass "tampered bundle refused" || fail "tampered: $bad"
	# The tampered upload removed the staged good one; stage it again and install.
	curl -sk -b "$JAR" -H "X-SJB-CSRF: $CSRF" --data-binary @"$WORK/good.upgrade" "$UI/ui/api/upgrade" >/dev/null
	start=$(ui -d '{}' "$UI/ui/api/upgrade/start")
	sleep 5
	wait_upgrade
	st=$(upstatus)
	[[ $start == *started* && $(root_run cat /etc/ngfw-version) == $V1 && $st == *'"result": "ok"'* ]] &&
		pass "upgrade from the web UI: now $V1" || fail "UI upgrade: start=$start status=$st"
	rev=$(root_run fwctl status | grep -o '"running_revision": [0-9]*' | grep -o '[0-9]*$')
	[[ $rev == "$REV_BEFORE" ]] && root_run nft list chain inet ngfw forward | grep -q ui-block-telnet &&
		pass "config and ruleset kept across the upgrade (revision $rev)" || fail "after upgrade: revision $rev"

	root_run "cat > /tmp/broken.upgrade" <"$WORK/broken.upgrade"
	out=$(root_run fwctl upgrade apply /tmp/broken.upgrade 2>&1)
	[[ $out == *"previous version restored"* && $(root_run cat /etc/ngfw-version) == $V1 ]] &&
		pass "bundle whose ngfwd fails: previous version restored" || fail "broken bundle: $out"
	[[ $(root_run systemctl is-active ngfwd) == active ]] && pass "ngfwd running after the failed upgrade" || fail "ngfwd not active"

	out=$(root_run fwctl upgrade rollback 2>&1)
	# ngfwd can still be activating just after the rollback restarts it.
	act=
	for _ in $(seq 15); do
		act=$(root_run systemctl is-active ngfwd)
		[[ $act == active ]] && break
		sleep 2
	done
	[[ $(root_run cat /etc/ngfw-version) == "$ORIG" && $act == active ]] &&
		pass "fwctl upgrade rollback returns to $ORIG" || fail "rollback: ngfwd $act: $out"
	st=$(cli_run show status)
	[[ $st == *running_revision* && $(root_run id -nG "$ADMIN") != *sudo* ]] &&
		pass "after rollback $ADMIN is still captive (undo, then $ORIG set it up again)" || fail "after rollback: $st"
else
	fail "upgrade checks need Go and the signing key at $SIGNING_KEY"
fi

root_run "apt-get update -qq" >/dev/null 2>&1 &&
	pass "appliance reaches the Debian mirrors (apt-get update)" || fail "apt-get update failed"


echo
(( FAILS == 0 )) && echo "BOOT TEST: all checks passed" || { echo "BOOT TEST: $FAILS failed"; exit 1; }
