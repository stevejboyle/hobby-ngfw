#!/usr/bin/env bash
# Soak test: boot the appliance in QEMU (VMware device models, as
# boot-test.sh does) and exercise it continuously for DURATION, recording
# resource use and every unexpected result. Test tooling; not shipped.
#
# Usage: deploy/appliance/soak-test.sh build/appliance/sjb-os-<v>.raw [DURATION]
#   DURATION: e.g. 20m (the default, for routine runs), 2h, 24h.
#   SOAK_INTERVAL: seconds per round (default 60).
#   SOAK_OUT: where the results go (default build/soak-<time>).
# Needs what boot-test.sh needs (qemu-system-x86_64, sshpass, curl,
# python3) plus net-snmp's snmpget (nix shell nixpkgs#net-snmp).
#
# Every round:
#   traffic: an allowed HTTP request (200), a denied port (no answer), the
#     same server through a port forward reached via hairpin NAT (200), an
#     IPS test signature (blocked), and a long-lived TCP session that must
#     keep answering through every commit
#   monitoring: a Prometheus scrape (latency, every section current) and an
#     SNMP v3 poll (latency, ngfwd up); every other round also scrapes 20
#     times in parallel while timing a transfer (throughput and latency
#     with and without monitoring load)
#   recorded: ngfwd CPU and memory, its threads and child processes,
#     sessions, service restarts (ngfwd, snmpd, sjb-ips, appidd), disk use
#     and journal size
# Every 5th round: a valid commit (timed) and an invalid one (must be
# refused). Every 7th: snmpd killed (it must be running again within 90 s).
# Every 10th: an SNMP credential added, rotated and deleted.
#
# The run fails (exit 1) on any unexpected result; the report says which.
# It never claims a duration it didn't run: the report gives the actual
# start and end times.
set -uo pipefail

RAW=${1:?usage: soak-test.sh DISK.raw [DURATION]}
DURATION=${2:-20m}
INTERVAL=${SOAK_INTERVAL:-60}
SRC=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${SOAK_OUT:-$SRC/build/soak-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
WORK=$(mktemp -d)
LOG=$WORK/console.log
SSH_PORT=${SSH_PORT:-2322}
API_PORT=${API_PORT:-18543}
SNMP_PORT=${SNMP_PORT:-18261}

secs() { # 20m, 2h, 24h, 90s -> seconds
	local v=$1
	case $v in
	*h) echo $((${v%h} * 3600)) ;;
	*m) echo $((${v%m} * 60)) ;;
	*s) echo "${v%s}" ;;
	*) echo "$v" ;;
	esac
}
TOTAL=$(secs "$DURATION")
FAILS=0
EVENTS=$OUT/events.log
CSV=$OUT/samples.csv
note() { echo "$(date -u +%FT%TZ) $*" | tee -a "$EVENTS"; }
bad() { FAILS=$((FAILS + 1)); note "FAIL $*"; }

ssh-keygen -q -t ed25519 -N '' -C sjb-soak -f "$WORK/root_key"
ROOTPW=$(LC_ALL=C tr -dc 'A-HJ-NP-Za-km-z2-9' </dev/urandom | head -c 16)
qemu-system-x86_64 -m 4096 -smp 2 -cpu max -display none -serial "file:$LOG" \
	-fw_cfg "name=opt/sjb/root_ssh_key,file=$WORK/root_key.pub" -fw_cfg "name=opt/sjb/root_password,string=$ROOTPW" \
	-device pvscsi,id=scsi0 \
	-drive "file=$RAW,format=raw,if=none,id=d0,snapshot=on" \
	-device scsi-hd,drive=d0,bus=scsi0.0 \
	-netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22,hostfwd=tcp:127.0.0.1:$API_PORT-:8443,hostfwd=udp:127.0.0.1:$SNMP_PORT-:161" \
	-device vmxnet3,netdev=mgmt,addr=0x10 \
	-netdev user,id=inside,restrict=on,net=10.99.0.0/24 \
	-device vmxnet3,netdev=inside,addr=0x11 \
	-netdev user,id=outside,net=10.98.0.0/24 \
	-device vmxnet3,netdev=outside,addr=0x12 &
QEMU=$!
trap 'kill $QEMU 2>/dev/null; rm -rf "$WORK"' EXIT
echo "booting (console: $LOG) ..."
for _ in $(seq 600); do
	grep -q 'SJB-OS ready' "$LOG" 2>/dev/null && break
	kill -0 $QEMU 2>/dev/null || { echo "qemu exited"; exit 1; }
	sleep 1
done
# The serial getty can print the password well after the ready line on a
# slow emulated boot: wait for it, as boot-test.sh does.
for _ in $(seq 60); do grep -aq 'initial password: ' "$LOG" && break; sleep 1; done
PW=$(grep -ao 'initial password: [A-Za-z0-9]*' "$LOG" | tail -1 | awk '{print $3}')
[[ -n $PW ]] || { echo "no admin password on the console"; exit 1; }
SSHOPTS=(-q -p "$SSH_PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=30)
retry255() {
	local rc
	for _ in 1 2 3 4 5; do
		"$@"
		rc=$?
		((rc != 255)) && return $rc
		sleep 3
	done
	return $rc
}
root_run() { retry255 ssh "${SSHOPTS[@]}" -i "$WORK/root_key" -o IdentitiesOnly=yes -o BatchMode=yes root@127.0.0.1 "$@"; }
cli() { retry255 sshpass -p "$PW" ssh "${SSHOPTS[@]}" -T -o PubkeyAuthentication=no admin@127.0.0.1 <<<"$1" 2>&1; }
for _ in $(seq 20); do root_run true && break; sleep 3; done
root_run true || { echo "no root login"; exit 1; }
VERSION=$(root_run cat /etc/ngfw-version)
for _ in $(seq 90); do [[ $(root_run "dpkg-query -W -f='\${db:Status-Status}' suricata snmpd" 2>/dev/null) == installedinstalled ]] && break; sleep 2; done

# --- setup: client and server behind the firewall --------------------------------
root_run 'set -e
	ip link add sk1 type veth peer name skc0; ip addr add 10.93.0.1/24 dev sk1; ip link set sk1 up
	ip link add sk2 type veth peer name sks0; ip addr add 10.94.0.1/24 dev sk2; ip link set sk2 up
	ip netns add skc; ip link set skc0 netns skc; ip -n skc addr add 10.93.0.2/24 dev skc0
	ip -n skc link set skc0 up; ip -n skc link set lo up; ip -n skc route add default via 10.93.0.1
	ip netns add sks; ip link set sks0 netns sks; ip -n sks addr add 10.94.0.2/24 dev sks0
	ip -n sks link set sks0 up; ip -n sks link set lo up; ip -n sks route add default via 10.94.0.1
	cat > /root/traffic.py' <"$SRC/deploy/appliance/boot-ips-traffic.py"
root_run 'nohup ip netns exec sks python3 /root/traffic.py server >/dev/null 2>&1 &'
# A listener on a port no rule allows: the denied-traffic check must time
# out here, where an allowed connection would succeed.
root_run 'nohup ip netns exec sks python3 -m http.server 8081 --bind 10.94.0.2 >/dev/null 2>&1 &'
# A long-lived session: one TCP connection to the echo server, a line every
# 5 s; it logs "ok" or "lost" each time.
root_run 'cat > /root/session.py' <<'EOF'
import socket, sys, time
s = socket.create_connection(("10.94.0.2", 9099), timeout=10)
n = 0
while True:
    n += 1
    try:
        s.sendall(b"line %d\n" % n)
        ok = s.recv(64).startswith(b"line")
    except OSError:
        ok = False
    print(time.strftime("%H:%M:%S"), "ok" if ok else "lost", flush=True)
    if not ok:
        sys.exit(1)
    time.sleep(5)
EOF
A1='soak-auth-pass-1' P1='soak-priv-pass-1'
setup=$'request snmp credential add soak v3 auth sha256 priv aes\n'"$A1"$'\n'"$A1"$'\n'"$P1"$'\n'"$P1"$'\n'
setup+=$'configure\nset zone soakc\nset zone soaks\nset interface sk1 zone soakc address 10.93.0.1/24\nset interface sk2 zone soaks address 10.94.0.1/24\n'
setup+=$'set address soak-srv cidr 10.94.0.2\nset service echo protocol tcp ports 9099\nset service web8080 protocol tcp ports 8080\n'
setup+=$'set rule soak-web from soakc to soaks destination soak-srv service web8080 action allow ips-profile default\n'
setup+=$'set rule soak-echo from soakc to soaks destination soak-srv service echo action allow\n'
setup+=$'set nat soak-fwd type port-forward interface sk2 protocol tcp public-port 18080 server soak-srv server-port 8080\n'
setup+=$'set snmp enabled on\nset snmp v3-users soak\ncommit -m "soak setup"\nexit\nexit\n'
out=$(cli "$setup")
[[ $out == *"committed revision"* ]] || { echo "setup commit failed: $out"; exit 1; }
KEY=$(cli $'request api-key add soak-prom scopes metrics:read\nexit\n' | grep -o '^  [A-Za-z0-9_-]\{40,\}' | tr -d ' ')
[[ -n $KEY ]] || { echo "no metrics key"; exit 1; }
for _ in $(seq 120); do [[ $(cli $'show ips\nexit\n') == *INSPECTING* ]] && break; sleep 5; done
root_run 'nohup ip netns exec skc python3 /root/session.py >/root/session.log 2>&1 &'
sleep 3

V3=(-v3 -u soak -l authPriv -a SHA-256 -A "$A1" -x AES -X "$P1" -t 5 -r 1 -On)
export MIBS=
get() { root_run "ip netns exec skc python3 /root/traffic.py client $1 10.93.0.2 $2"; }
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }
echo "round,time,ngfwd_cpu_pct,ngfwd_rss_kb,ngfwd_threads,ngfwd_children,sessions,scrape_ms,scrape_sections_current,snmp_ms,commit_ms,xfer_mbps,xfer_mbps_loaded,ping_ms,restarts_ngfwd,restarts_snmpd,restarts_ips,restarts_appidd,disk_used_kb,journal_kb" >"$CSV"
note "soak start: SJB-OS $VERSION, duration $DURATION ($TOTAL s), round every $INTERVAL s"
START=$(date +%s)
round=0
while (($(date +%s) - START < TOTAL)); do
	round=$((round + 1))
	t0=$(date +%s)
	# Traffic.
	[[ $(get 10.94.0.2 plain) == 200 ]] || bad "round $round: allowed HTTP failed"
	[[ $(get 10.94.0.2 SJB-IPS-TEST-CRITICAL) == blocked ]] || bad "round $round: IPS test signature not blocked"
	root_run "ip netns exec skc timeout 4 bash -c 'echo > /dev/tcp/10.94.0.2/8081'" 2>/dev/null && bad "round $round: a denied port answered"
	hp=$(root_run "ip netns exec skc python3 -c \"
import urllib.request
try: print(urllib.request.urlopen('http://10.94.0.1:18080/plain', timeout=6).status)
except Exception as e: print('fail', e)\"")
	[[ $hp == 200 ]] || bad "round $round: hairpin port forward: $hp"
	[[ $(root_run 'tail -1 /root/session.log') == *ok* ]] || bad "round $round: the long-lived session was lost: $(root_run 'tail -3 /root/session.log')"
	# Monitoring.
	s0=$(now_ms)
	code=$(curl -sk -o "$WORK/m.txt" -w '%{http_code}' -H "Authorization: Bearer $KEY" "https://127.0.0.1:$API_PORT/metrics")
	scrape_ms=$(($(now_ms) - s0))
	cur=$(grep -c 'sjbos_collection_state{section="[a-z]*",state="current"} 1' "$WORK/m.txt")
	[[ $code == 200 ]] || bad "round $round: scrape returned $code"
	s0=$(now_ms)
	up=$(snmpget "${V3[@]}" "127.0.0.1:$SNMP_PORT" .1.3.6.1.4.1.8072.9999.9999.7.1.4.0 2>&1)
	snmp_ms=$(($(now_ms) - s0))
	[[ $up == *"INTEGER: 1"* ]] || bad "round $round: SNMP poll: $up"
	# Throughput and latency, with monitoring load every other round.
	xfer() { root_run "ip netns exec skc python3 -c \"
import socket, time
s = socket.create_connection(('10.94.0.2', 9099), timeout=10)
data = b'x' * 65535 + b'\\\\n'
t = time.time(); n = 0
while time.time() - t < 3:
    s.sendall(data); n += len(data); s.recv(1 << 20)
print(round(n * 8 / (time.time() - t) / 1e6, 1))\"" 2>/dev/null; }
	mbps=$(xfer)
	loaded=""
	if ((round % 2 == 0)); then
		for _ in $(seq 20); do curl -sk -o /dev/null -H "Authorization: Bearer $KEY" "https://127.0.0.1:$API_PORT/metrics" & done
		loaded=$(xfer)
		wait
	fi
	ping=$(root_run "ip netns exec skc ping -c 5 -i 0.2 -q 10.94.0.2" | awk -F/ '/rtt/ {print $5}')
	# Periodic commits.
	commit_ms=""
	if ((round % 5 == 0)); then
		c0=$(now_ms)
		out=$(cli $'configure\nset address soak-tick cidr 10.93.0.'"$((round % 200 + 10))"$'\ncommit -m "soak tick"\nexit\nexit\n')
		commit_ms=$(($(now_ms) - c0))
		[[ $out == *"committed revision"* ]] || bad "round $round: valid commit failed: ${out: -200}"
		out=$(cli $'configure\nset rule soak-bad from no-such-zone to soaks action allow\ncommit -m "soak invalid"\nexit\nrevert\nexit\n')
		[[ $out != *"committed revision"* ]] || bad "round $round: an invalid commit was accepted"
	fi
	if ((round % 7 == 0)); then
		root_run 'systemctl kill -s KILL snmpd' >/dev/null 2>&1
		back=0
		for _ in $(seq 45); do [[ $(snmpget "${V3[@]}" "127.0.0.1:$SNMP_PORT" .1.3.6.1.2.1.1.3.0 2>&1) == *Timeticks* ]] && back=1 && break; sleep 2; done
		((back)) && note "round $round: snmpd killed, back" || bad "round $round: snmpd not back within 90 s after a kill"
	fi
	if ((round % 10 == 0)); then
		out=$(cli $'request snmp credential add soak-tmp v2c\ntmp-community-1\ntmp-community-1\nrequest snmp credential change soak-tmp v2c\ntmp-community-2\ntmp-community-2\nrequest snmp credential delete soak-tmp\nexit\n')
		[[ $out == *"soak-tmp added"* && $out == *"soak-tmp changed"* && $out == *"soak-tmp deleted"* ]] || bad "round $round: credential cycle: ${out: -300}"
	fi
	# Resources.
	res=$(root_run 'p=$(systemctl show -p MainPID --value ngfwd)
		echo "$(ps -o %cpu=,rss= -p $p | xargs) $(awk "/^Threads/ {print \$2}" /proc/$p/status) $(pgrep -c -P $p)"
		cat /proc/sys/net/netfilter/nf_conntrack_count
		for u in ngfwd snmpd sjb-ips appidd; do systemctl show -p NRestarts --value $u; done | xargs
		df -k --output=used / | tail -1 | xargs
		du -sk /var/log/journal 2>/dev/null | cut -f1')
	read -r cpu rss thr kids <<<"$(sed -n 1p <<<"$res")"
	sess=$(sed -n 2p <<<"$res")
	read -r rn rs ri ra <<<"$(sed -n 3p <<<"$res")"
	disk=$(sed -n 4p <<<"$res")
	jour=$(sed -n 5p <<<"$res")
	echo "$round,$(date -u +%FT%TZ),$cpu,$rss,$thr,$kids,$sess,$scrape_ms,$cur,$snmp_ms,$commit_ms,$mbps,$loaded,$ping,$rn,$rs,$ri,$ra,$disk,$jour" >>"$CSV"
	echo "round $round: scrape ${scrape_ms} ms ($cur sections current), snmp ${snmp_ms} ms, ngfwd rss ${rss} kB, ${thr} threads, ${kids} children, ${sess} sessions, ${mbps} Mb/s${loaded:+ (${loaded} loaded)}, failures so far $FAILS"
	sleep $((INTERVAL - ($(date +%s) - t0) > 0 ? INTERVAL - ($(date +%s) - t0) : 0))
done
END=$(date +%s)

# --- report -----------------------------------------------------------------------
python3 - "$CSV" "$OUT/report.txt" "$VERSION" "$DURATION" "$START" "$END" "$FAILS" "$EVENTS" <<'EOF'
import csv, sys, time
path, out, version, duration, start, end, fails, events = sys.argv[1:]
rows = list(csv.DictReader(open(path)))
def col(name):
    return [float(r[name]) for r in rows if r[name] not in ("", None)]
def stat(name, unit=""):
    v = col(name)
    if not v:
        return f"{name}: no samples"
    return f"{name}: first {v[0]:g}{unit}, last {v[-1]:g}{unit}, min {min(v):g}{unit}, max {max(v):g}{unit}, mean {sum(v)/len(v):.1f}{unit}"
lines = [
    f"SJB-OS {version} soak test",
    f"asked for {duration}; ran {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(start)))} to {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(end)))} UTC ({(int(end) - int(start)) / 3600:.2f} h, {len(rows)} rounds)",
    f"unexpected results: {fails}" + ("" if fails == "0" else f" (see {events})"),
    "",
]
for name, unit in [("ngfwd_rss_kb", " kB"), ("ngfwd_cpu_pct", "%"), ("ngfwd_threads", ""), ("ngfwd_children", ""), ("sessions", ""),
                   ("scrape_ms", " ms"), ("scrape_sections_current", ""), ("snmp_ms", " ms"), ("commit_ms", " ms"),
                   ("xfer_mbps", " Mb/s"), ("xfer_mbps_loaded", " Mb/s"), ("ping_ms", " ms"),
                   ("restarts_ngfwd", ""), ("restarts_snmpd", ""), ("restarts_ips", ""), ("restarts_appidd", ""),
                   ("disk_used_kb", " kB"), ("journal_kb", " kB")]:
    lines.append(stat(name, unit))
lines.append("")
lines.append("Not measured: Go goroutine counts (ngfwd has no debug endpoint; its thread count is recorded instead).")
open(out, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
EOF
note "soak end: $FAILS unexpected result(s); results in $OUT"
((FAILS == 0))
