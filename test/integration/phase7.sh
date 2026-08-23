#!/usr/bin/env bash
# Phase 7 exit test: user accounts, roles, signup toggle, node key
# rotation, audit log.
#
#   - admin bootstrap (old password-only login body still works)
#   - admin creates a member; the member sees ONLY their own devices
#     and is 403'd from ACLs / route approvals / user management
#   - devices enroll under the account whose setup key they use
#   - open signup is 404 until toggled on, then creates member accounts
#   - `overmesh rotate-key` swaps the WG key live: connectivity
#     recovers within seconds and the audit log records the rotation
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase7.XXXXXX)"
NET=om-p7-net; SRV=om-p7-srv; A=om-p7-a; B=om-p7-b
SRV_IP=10.235.0.1; A_IP=10.235.0.2; B_IP=10.235.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=phase7-admin-password
MEMBER_PW=phase7-member-pass
PASS=0; FAIL=0

log() { echo "[phase7] $*"; }
ns()  { ip netns exec "$@"; }
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"; PASS=$((PASS+1))
  else
    echo "  FAIL  $desc"; FAIL=$((FAIL+1))
  fi
}
check_not() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  FAIL  $desc"; FAIL=$((FAIL+1))
  else
    echo "  PASS  $desc"; PASS=$((PASS+1))
  fi
}

OK=0
cleanup() {
  set +e
  # Kill this run's daemons (they are not netns-bound processes and
  # would otherwise linger, spamming reconnect errors into kept logs).
  pkill -f "socket $WORK" 2>/dev/null
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase7] logs kept in $WORK"
    tail -n 25 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build'"; exit 1; }
done

log "topology + control plane"
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p7v$i" type veth peer name "p7b$i"
  ip link set "p7v$i" netns "$n"
  ip link set "p7b$i" netns "$NET"
  ns $NET ip link set "p7b$i" master br0
  ns $NET ip link set "p7b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p7v$i"
  ns "$n" ip link set "p7v$i" up
  i=$((i+1))
done

ns $SRV "$BIN/overmesh-server" -http "$HTTP" -grpc "$GRPC" -stun "$SRV_IP:3478" \
  -state-dir "$WORK/server" -admin-password "$ADMIN_PW" \
  >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  ns $SRV curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
check "server healthz" ns $SRV curl -fsS "http://$HTTP/healthz"

# api <cookie-jar> <method> <path> [data]
api() {
  local jar="$1" m="$2" p="$3" d="${4:-}"
  if [ -n "$d" ]; then
    ns $SRV curl -fsS -b "$jar" -X "$m" "http://$HTTP$p" -d "$d"
  else
    ns $SRV curl -fsS -b "$jar" -X "$m" "http://$HTTP$p"
  fi
}
http_code() { # <jar> <method> <path> [data]
  local jar="$1" m="$2" p="$3" d="${4:-}"
  ns $SRV curl -s -o /dev/null -w '%{http_code}' -b "$jar" -X "$m" "http://$HTTP$p" ${d:+-d "$d"}
}

log "logins: legacy body, username body, wrong password"
check "legacy password-only login body still works (admin)" bash -c \
  "ip netns exec $SRV curl -fsS -c '$WORK/legacy.jar' -X POST 'http://$HTTP/api/login' \
   -d '{\"password\":\"$ADMIN_PW\"}' | grep -q '\"role\":\"admin\"'"
check "username login works" bash -c \
  "ip netns exec $SRV curl -fsS -c '$WORK/admin.jar' -X POST 'http://$HTTP/api/login' \
   -d '{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}' | grep -q '\"role\":\"admin\"'"
check_not "wrong password rejected" ns $SRV curl -fsS -X POST "http://$HTTP/api/login" \
  -d "{\"username\":\"admin\",\"password\":\"nope-nope-nope\"}"

log "signup is off by default"
check "signup returns 404 while disabled" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -X POST 'http://$HTTP/api/signup' \
    -d '{\"username\":\"walkin\",\"password\":\"walkinpass1\"}') = 404 ]"

log "admin creates member 'peter'; member logs in"
check "create member via /api/users" api "$WORK/admin.jar" POST /api/users \
  "{\"username\":\"peter\",\"password\":\"$MEMBER_PW\",\"role\":\"member\"}"
check "member login works" bash -c \
  "ip netns exec $SRV curl -fsS -c '$WORK/member.jar' -X POST 'http://$HTTP/api/login' \
   -d '{\"username\":\"peter\",\"password\":\"$MEMBER_PW\"}' | grep -q '\"role\":\"member\"'"

log "RBAC: member is 403'd from admin surfaces"
check "member cannot list users (403)" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -b '$WORK/member.jar' \
    'http://$HTTP/api/users') = 403 ]"
check "member cannot edit ACLs (403)" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -b '$WORK/member.jar' \
    -X PUT 'http://$HTTP/api/acl' -d '{\"rules\":[]}') = 403 ]"
check "member cannot read the audit log (403)" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -b '$WORK/member.jar' \
    'http://$HTTP/api/audit') = 403 ]"

log "enrollment: node-a with an admin key, node-b with peter's key"
ADMIN_KEY=$(api "$WORK/admin.jar" POST /api/setupkeys '{"reusable":true}' \
  | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
MEMBER_KEY=$(api "$WORK/member.jar" POST /api/setupkeys '{"reusable":true}' \
  | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$ADMIN_KEY" ] && [ -n "$MEMBER_KEY" ] || { echo "no setup keys"; exit 1; }

ns $A env OM_HOSTNAME=node-a "$BIN/overmeshd" \
  -state-dir "$WORK/a" -socket "$WORK/a.sock" -wg-mode userspace \
  >"$WORK/a.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$WORK/a.sock" ] && break; sleep 0.2; done
ns $A "$BIN/overmesh" up -socket "$WORK/a.sock" -server "$GRPC" -key "$ADMIN_KEY"

ns $B env OM_HOSTNAME=node-b "$BIN/overmeshd" \
  -state-dir "$WORK/b" -socket "$WORK/b.sock" -wg-mode userspace \
  >"$WORK/b.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$WORK/b.sock" ] && break; sleep 0.2; done
ns $B "$BIN/overmesh" up -socket "$WORK/b.sock" -server "$GRPC" -key "$MEMBER_KEY"

get_ip() { ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n "s/.*\"$3\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
A4=$(get_ip $A "$WORK/a.sock" ipv4); B4=$(get_ip $B "$WORK/b.sock" ipv4)
log "overlay: a=$A4 b=$B4"

ping_ok() {
  for _ in $(seq 1 "${3:-15}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "a -> b connectivity" ping_ok $A "$B4"

log "ownership: member sees only their device; admin sees both + owner"
check "admin sees 2 devices" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/admin.jar' 'http://$HTTP/api/devices' \
   | python3 -c 'import json,sys; assert len(json.load(sys.stdin)) == 2'"
check "admin sees node-b owned by peter" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/admin.jar' 'http://$HTTP/api/devices' \
   | python3 -c 'import json,sys; d=[x for x in json.load(sys.stdin) if x[\"hostname\"]==\"node-b\"][0]; assert d[\"owner\"]==\"peter\"'"
check "member sees exactly their own device" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/member.jar' 'http://$HTTP/api/devices' \
   | python3 -c 'import json,sys; ds=json.load(sys.stdin); assert len(ds)==1 and ds[0][\"hostname\"]==\"node-b\"'"
A_ID=$(api "$WORK/admin.jar" GET /api/devices | python3 -c \
  'import json,sys; print([x for x in json.load(sys.stdin) if x["hostname"]=="node-a"][0]["id"])')
check "member cannot delete admin's device (403)" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -b '$WORK/member.jar' \
    -X DELETE 'http://$HTTP/api/devices/$A_ID') = 403 ]"
check "member sees only their own setup keys" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/member.jar' 'http://$HTTP/api/setupkeys' \
   | python3 -c 'import json,sys; ks=json.load(sys.stdin); assert len(ks)==1 and ks[0][\"owner\"]==\"peter\"'"

log "signup toggle"
check "admin enables signup" api "$WORK/admin.jar" PUT /api/settings/signup '{"enabled":true}'
check "signup now creates a member" bash -c \
  "ip netns exec $SRV curl -fsS -c '$WORK/newbie.jar' -X POST 'http://$HTTP/api/signup' \
   -d '{\"username\":\"newbie\",\"password\":\"newbiepass99\"}' | grep -q '\"role\":\"member\"'"
check "admin disables signup again" api "$WORK/admin.jar" PUT /api/settings/signup '{"enabled":false}'
check "signup 404 again" bash -c \
  "[ \$(ip netns exec $SRV curl -s -o /dev/null -w '%{http_code}' -X POST 'http://$HTTP/api/signup' \
    -d '{\"username\":\"late\",\"password\":\"latelate99\"}') = 404 ]"

log "node key rotation on node-b, live"
OLD_KEY=$(python3 -c "import json;print(json.load(open('$WORK/b/overmeshd.json'))['node_private_hex'])")
check "overmesh rotate-key succeeds" ns $B "$BIN/overmesh" rotate-key -socket "$WORK/b.sock"
NEW_KEY=$(python3 -c "import json;print(json.load(open('$WORK/b/overmeshd.json'))['node_private_hex'])")
check "state file holds a new private key" test "$OLD_KEY" != "$NEW_KEY"
check "a -> b connectivity recovers after rotation" ping_ok $A "$B4" 30
check "b -> a connectivity after rotation" ping_ok $B "$A4" 15

log "audit log has the trail"
AUDIT=$(api "$WORK/admin.jar" GET '/api/audit?limit=200')
for action in login user.create setupkey.create device.register device.key-rotated settings.signup user.signup; do
  check "audit contains $action" bash -c "echo '$AUDIT' | grep -q '\"action\":\"$action\"'"
done

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
