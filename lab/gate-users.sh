#!/usr/bin/env bash
# Users gate: multiple users and roles on a real Debian system. Unix logins
# created and locked by ngfwd, the management socket naming its caller from
# the kernel (SO_PEERCRED), each role's limits, per-area config checks,
# verified commit authors, SSH keys for sshd, the PAM lockout (pamtester),
# and sjb-migrate's apply, undo (rollback to a version without users) and
# apply again.
#
# It creates users and rewrites PAM files, so it only runs in a throwaway
# container (see `make lab-gate-users`). Needs root, openssh-server,
# pamtester and procps. Binaries from $BIN (./bin).
set -uo pipefail

if [[ ! -e /.dockerenv && ${SJB_GATE_USERS:-} != yes ]]; then
	echo "gate-users changes accounts and PAM: run it in a container (make lab-gate-users), or set SJB_GATE_USERS=yes on a throwaway machine" >&2
	exit 2
fi

BIN=$(cd "${BIN:-./bin}" && pwd)
SRC=$(pwd)
SOCK=/run/ngfw/ngfwd.sock
STUBS=$(mktemp -d)
FAILS=0
NGFWD=

cleanup() {
	[[ -n $NGFWD ]] && kill "$NGFWD" 2>/dev/null
	wait 2>/dev/null
	(( FAILS > 0 )) && { echo "--- ngfwd log ---"; cat /tmp/ngfwd.log 2>/dev/null; }
}
trap cleanup EXIT

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS + 1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }
fw() { "$BIN/fwctl" -socket "$SOCK" "$@"; }
as() { local u=$1; shift; runuser -u "$u" -- "$BIN/fwctl" -socket "$SOCK" "$@"; }
cli() { fw shell -c "$*"; }

# sjb-migrate needs systemd; a container has none.
for t in systemctl loginctl systemd-run; do printf '#!/bin/sh\nexit 1\n' >"$STUBS/$t"; chmod +x "$STUBS/$t"; done
printf '#!/bin/sh\nexit 0\n' >"$STUBS/ok"; chmod +x "$STUBS/ok"
migrate() { PATH=$STUBS:$PATH "$SRC/deploy/appliance/rootfs/usr/local/sbin/sjb-migrate" "$@"; }

start_ngfwd() {
	"$BIN/ngfwd" -state /var/lib/ngfw -socket "$SOCK" -socket-group sjbadm -nft "$STUBS/ok" -conntrack "$STUBS/ok" \
		-frr '' -kea '' -ips-dir '' -tlsd '' -ip '' -api-keys /etc/ngfw/api-keys \
		-bootstrap "$SRC/examples/lab.yaml" >>/tmp/ngfwd.log 2>&1 &
	NGFWD=$!
	for _ in $(seq 50); do [[ -S $SOCK ]] && return 0; sleep 0.1; done
	fail "ngfwd did not start"; exit 1
}
stop_ngfwd() { kill "$NGFWD"; wait "$NGFWD" 2>/dev/null; NGFWD=; }

KEY_ADMIN="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGl0IHN0b3BzIGp1bmsgYXQgdGhlIGJvcmRlcnMgdG9k admin@deploy"
KEY_BOB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHNlY29uZCBrZXkgZm9yIHRlc3RzIG9ubHkgcGxlYXMh bob@laptop"

# --- the image, then first boot ------------------------------------------------
echo "== image and first boot"
useradd -m -s /bin/bash -c "SJB-OS administrator" admin
passwd -l admin >/dev/null
install -m 644 "$SRC/deploy/appliance/rootfs/etc/ssh/sshd_config.d/10-ngfw.conf" /etc/ssh/sshd_config.d/10-ngfw.conf
install -d -m 700 /etc/ngfw /var/lib/ngfw
echo "tagger tags:write $(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')" >/etc/ngfw/api-keys
# First boot: admin's deploy key first, then the password, which creates the
# user database and imports the key.
install -d -m 700 -o admin -g admin /home/admin/.ssh
echo "$KEY_ADMIN" >/home/admin/.ssh/authorized_keys
printf 'admin-first-password\n' | fw web-passwd -user admin -file /etc/ngfw/web-users 2>/dev/null
check "first boot created the user database" test -s /etc/ngfw/users.json
check "admin's deploy key imported" grep -q "admin@deploy" /etc/ngfw/users.json
check "old web user file kept for rollbacks" grep -q '^admin pbkdf2-sha256' /etc/ngfw/web-users

start_ngfwd
migrate apply >/tmp/migrate.log 2>&1 || { fail "sjb-migrate apply: $(cat /tmp/migrate.log)"; }
check "admin's key written for sshd" grep -q "admin@deploy" /etc/ssh/sjb-keys/admin
check "admin's shell is the captive CLI" test "$(getent passwd admin | cut -d: -f7)" = /usr/lib/sjb-os/login-shell
check "sshd PAM uses the lockout stack" grep -qx '@include sjb-auth' /etc/pam.d/sshd
check "console PAM uses the lockout stack" grep -qx '@include sjb-auth-console' /etc/pam.d/login
ssh-keygen -A >/dev/null 2>&1
check "sshd accepts the SSH policy" sshd -t
check "sjbadm members get the captive CLI and sjb-keys" bash -c "sshd -T -C user=admin,host=x,addr=10.0.0.1 | grep -q 'authorizedkeysfile /etc/ssh/sjb-keys/%u'"

# --- users from the CLI (root is a superuser) ---------------------------------------
echo "== users"
printf 'alice-password-1\nalice-password-1\n' | cli request user add alice role admin >/dev/null
printf 'bob-password-12\nbob-password-12\n' | cli request user add bob role read-only >/dev/null
check "alice's login created by ngfwd" bash -c 'getent passwd alice | grep -q ":SJB-OS user:/nonexistent:/usr/lib/sjb-os/login-shell$"'
check "alice is in sjbadm" bash -c 'id -nG alice | grep -qw sjbadm'
check "alice has a login password" bash -c '[[ $(passwd -S alice | cut -d" " -f2) == P ]]'
check "a name already on the system is refused" bash -c "! printf 'x-password-123\nx-password-123\n' | $BIN/fwctl -socket $SOCK shell -c 'request user add daemon role admin' 2>/dev/null"
cli show users | grep -q "bob  *read-only" && pass "show users" || fail "show users: $(cli show users)"

# --- who is calling, and what they may do ---------------------------------------
echo "== roles over the socket"
check "alice (admin) sees status" as alice status
out=$(as alice shell -c "show whoami" 2>&1)
[[ $out == *"alice, role admin"* ]] && pass "alice is alice to ngfwd" || fail "whoami: $out"
check "bob (read-only) reads the config" as bob show running
check "bob can't load a config" bash -c "! runuser -u bob -- $BIN/fwctl -socket $SOCK load $SRC/examples/lab.yaml"
check "bob can't register tags" bash -c "! runuser -u bob -- $BIN/fwctl -socket $SOCK tags register 10.10.1.5 quarantine"
check "bob can't list users" bash -c "! runuser -u bob -- $BIN/fwctl -socket $SOCK shell -c 'show users'"
check "bob can't read tag API keys" bash -c "! runuser -u bob -- $BIN/fwctl -socket $SOCK shell -c 'show api-keys'"
check "alice can't add users" bash -c "! printf 'eve-password-12\neve-password-12\n' | runuser -u alice -- $BIN/fwctl -socket $SOCK shell -c 'request user add eve role superuser'"
useradd -M -s /usr/sbin/nologin outsider
check "a Unix user outside sjbadm can't reach the socket" bash -c "! runuser -u outsider -- $BIN/fwctl -socket $SOCK status"
usermod -aG sjbadm outsider
out=$(runuser -u outsider -- "$BIN/fwctl" -socket "$SOCK" status 2>&1)
[[ $out == *"not an SJB-OS user"* ]] && pass "an sjbadm member who isn't an SJB-OS user gets nothing" || fail "outsider: $out"
gpasswd -d outsider sjbadm >/dev/null

# The author is the caller, whatever the CLI says.
sed 's/hostname: fw-lab/hostname: fw-alice/' "$SRC/examples/lab.yaml" >/tmp/alice.yaml
as alice load /tmp/alice.yaml >/dev/null && SUDO_USER=mallory as alice commit -m "alice's change" >/dev/null
fw revisions | grep -q '"author": "cli:alice"' && pass "commit recorded as cli:alice" || fail "revisions: $(fw revisions | tail -12)"

# Custom role: policy only.
cli request role add policy-only description '"rules and objects"' >/dev/null
cli request role set policy-only policy change >/dev/null
cli request role set policy-only revisions view >/dev/null
cli request user set bob role policy-only >/dev/null
sed 's/hostname: fw-alice/hostname: fw-bob/' /tmp/alice.yaml >/tmp/bob-host.yaml
out=$(as bob load /tmp/bob-host.yaml 2>&1)
[[ $out == *"network"* ]] && pass "policy-only can't change the hostname" || fail "bob hostname: $out"
# Rules only: the allow-web rule stops logging.
awk '/- name: allow-web/{w=1} w && /log: true/{sub(/log: true/, "log: false"); w=0} {print}' /tmp/alice.yaml >/tmp/bob-rules.yaml
if as bob load /tmp/bob-rules.yaml >/dev/null 2>&1 && as bob commit -m "rules" >/dev/null 2>&1; then pass "policy-only changes and commits rules"; else fail "bob rules: $(as bob load /tmp/bob-rules.yaml 2>&1)"; fi

# SSH keys for sshd.
echo "$KEY_BOB" | cli request user ssh-key add bob >/dev/null
check "bob's key file for sshd" bash -c "grep -q bob@laptop /etc/ssh/sjb-keys/bob && [[ \$(stat -c %a /etc/ssh/sjb-keys/bob) == 644 ]]"

# --- PAM lockout (SSH and console) -----------------------------------------------
echo "== lockout"
if command -v pamtester >/dev/null; then
	for _ in 1 2 3 4 5; do echo wrong-password | pamtester sshd bob authenticate >/dev/null 2>&1; done
	check "SSH: bob locked after 5 wrong passwords" bash -c '! (echo bob-password-12 | pamtester sshd bob authenticate)'
	cli request user unlock bob >/dev/null
	check "SSH: unlocked by a superuser" bash -c 'echo bob-password-12 | pamtester sshd bob authenticate'
	for _ in 1 2 3 4 5 6; do echo wrong-password | pamtester login admin authenticate >/dev/null 2>&1; done
	check "console: admin never locked" bash -c 'echo admin-first-password | pamtester login admin authenticate'
else
	fail "pamtester not installed"
fi

# --- disable, then rollback to a version without users, then upgrade again -------
echo "== disable, rollback, upgrade"
cli request user set alice disabled yes >/dev/null
check "disabled alice: login locked" bash -c '[[ $(passwd -S alice | cut -d" " -f2) == L ]]'
check "disabled alice: out of sjbadm" bash -c '! id -nG alice | grep -qw sjbadm'
check "disabled alice: refused" bash -c "! runuser -u alice -- $BIN/fwctl -socket $SOCK status"

cli request user set alice disabled no >/dev/null
migrate undo 0.9.9-r08 >/tmp/undo.log 2>&1 || fail "sjb-migrate undo: $(cat /tmp/undo.log)"
check "undo: bob locked for the old version" bash -c '[[ $(passwd -S bob | cut -d" " -f2) == L ]] && ! id -nG bob | grep -qw sjbadm'
check "undo: admin's keys back in its home" grep -q "admin@deploy" /home/admin/.ssh/authorized_keys
check "undo: PAM back to Debian's" bash -c 'grep -qx "@include common-auth" /etc/pam.d/sshd && grep -qx "@include common-auth" /etc/pam.d/login && [[ ! -e /etc/pam.d/sjb-auth ]]'
check "undo: admin's web password still in the old file" grep -q '^admin pbkdf2-sha256' /etc/ngfw/web-users

stop_ngfwd
start_ngfwd
migrate apply >/tmp/migrate.log 2>&1 || fail "sjb-migrate apply again: $(cat /tmp/migrate.log)"
check "upgrade again: bob back in sjbadm and unlocked" bash -c 'id -nG bob | grep -qw sjbadm && [[ $(passwd -S bob | cut -d" " -f2) == P ]]'
check "upgrade again: PAM lockout back" grep -qx '@include sjb-auth' /etc/pam.d/sshd
check "upgrade again: bob still policy-only" bash -c "runuser -u bob -- $BIN/fwctl -socket $SOCK shell -c 'show whoami' | grep -q 'role policy-only'"

cli request user delete bob >/dev/null
check "deleted bob: login and key gone" bash -c '! getent passwd bob && [[ ! -e /etc/ssh/sjb-keys/bob ]]'
check "admin can't be deleted" bash -c "! $BIN/fwctl -socket $SOCK shell -c 'request user delete admin'"
check "user changes are in the log" grep -q 'msg="user deleted" user=bob by=root' /tmp/ngfwd.log

echo
if (( FAILS > 0 )); then echo "users gate: $FAILS failed"; exit 1; fi
echo "users gate: all passed"
