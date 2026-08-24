#!/usr/bin/env bash
# Phase 10 exit test: hardening & operations.
#
#   - web UI bound to localhost stays private; relay serves on its own
#     public port (41643) so nodes still get the fallback path
#   - /metrics reports nodes, netmap pushes, relay counters
#   - overmesh netcheck + bugreport work on a live node
#   - kill -9 the server -> established tunnels KEEP passing traffic
#     (data plane independent of control plane)
#   - backup/restore drill: restore the copied DB, daemons reconnect,
#     nothing re-enrolls
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase10.XXXXXX)"
NET=om-p10-net; SRV=om-p10-srv; A=om-p10-a; B=om-p10-b
SRV_IP=10.252.0.1; A_IP=10.252.0.2; B_IP=10.252.0.3
UI="127.0.0.1:8080"; GRPC="$SRV_IP:41641"; RELAY_PORT=41643
ADMIN_PW=phase10-test-password
PASS=0; FAIL=0

log() { echo "[phase10] $*"; }
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
  pkill -f "socket $WORK" 2>/dev/null
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase10] logs kept in $WORK"
    tail -n 30 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build'"; exit 1; }
done

log "topology + control plane (web UI on localhost ONLY)"
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p10v$i" type veth peer name "p10b$i"
  ip link set "p10v$i" netns "$n"
  ip link set "p10b$i" netns "$NET"
  ns $NET ip link set "p10b$i" master br0
  ns $NET ip link set "p10b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p10v$i"
  ns "$n" ip link set "p10v$i" up
  i=$((i+1))
done

start_server() {
  ns $SRV "$BIN/overmesh-server" -http "$UI" -grpc "$GRPC" -stun "$SRV_IP:3478" \
    -relay-listen "$SRV_IP:$RELAY_PORT" \
    -state-dir "$WORK/server" -admin-password "$ADMIN_PW" \
    >>"$WORK/server.log" 2>&1 &
  SRV_PID=$!
  for _ in $(seq 1 50); do
    ns $SRV curl -fsS "http://$UI/healthz" >/dev/null 2>&1 && break
    sleep 0.2
  done
}
start_server
check "server healthz on localhost" ns $SRV curl -fsS "http://$UI/healthz"

log "privacy: UI is local-only, relay is public on its own port"
check_not "web UI NOT reachable from the LAN" \
  ns $A curl -fsS -m 3 "http://$SRV_IP:8080/healthz"
check "relay healthz reachable from the LAN on :$RELAY_PORT" \
  ns $A curl -fsS -m 3 "http://$SRV_IP:$RELAY_PORT/healthz"

ns $SRV curl -fsS -c "$WORK/cookies" -X POST "http://$UI/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(ns $SRV curl -fsS -b "$WORK/cookies" -X POST "http://$UI/api/setupkeys" \
  -d '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$KEY" ] || { echo "no setup key"; exit 1; }

log "two daemons join"
for side in a b; do
  NSN=$([ "$side" = a ] && echo $A || echo $B)
  ns $NSN env OM_HOSTNAME="node-$side" "$BIN/overmeshd" \
    -state-dir "$WORK/$side" -socket "$WORK/$side.sock" -wg-mode userspace \
    >"$WORK/$side.log" 2>&1 &
  for _ in $(seq 1 50); do [ -S "$WORK/$side.sock" ] && break; sleep 0.2; done
  ns $NSN "$BIN/overmesh" up -socket "$WORK/$side.sock" -server "$GRPC" -key "$KEY"
done
get_ip() { ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n "s/.*\"$3\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
A4=$(get_ip $A "$WORK/a.sock" ipv4)
B4=$(get_ip $B "$WORK/b.sock" ipv4)

ping_ok() {
  for _ in $(seq 1 "${3:-20}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "a -> b connectivity" ping_ok $A "$B4"

log "metrics on the private listener"
METRICS="$WORK/metrics.txt"
ns $SRV curl -fsS "http://$UI/metrics" > "$METRICS"
check "metrics: 2 registered nodes" grep -q '^overmesh_nodes 2' "$METRICS"
check "metrics: 2 nodes online" grep -q '^overmesh_nodes_online 2' "$METRICS"
check "metrics: netmap pushes counted" bash -c \
  "awk '/^overmesh_netmap_pushes_total/ {exit (\$2 > 0 ? 0 : 1)}' '$METRICS'"
check "metrics: relay clients gauge present" grep -q '^overmesh_relay_clients' "$METRICS"

log "netcheck + bugreport on node-a"
NETCHECK="$WORK/netcheck.txt"
ns $A "$BIN/overmesh" netcheck -socket "$WORK/a.sock" > "$NETCHECK" 2>&1 || true
cat "$NETCHECK" | sed 's/^/    /'
check "netcheck: control plane ok" bash -c "grep '^control' '$NETCHECK' | grep -q 'ok ('"
check "netcheck: STUN mapped a public endpoint" bash -c "grep '^stun' '$NETCHECK' | grep -q 'public endpoint'"
check "netcheck: udp not blocked" bash -c "grep '^udp' '$NETCHECK' | grep -q 'ok'"
check "netcheck: relay reachable" bash -c "grep '^relay' '$NETCHECK' | grep -q 'ok ('"
check "bugreport contains status + netcheck" bash -c \
  "ip netns exec $A '$BIN/overmesh' bugreport -socket '$WORK/a.sock' | grep -q '== netcheck =='"

log "control-plane outage: kill -9 the server, tunnels must keep working"
kill -9 "$SRV_PID"
wait "$SRV_PID" 2>/dev/null || true
sleep 2
check "a -> b ping DURING server outage" ping_ok $A "$B4" 5
check "b -> a ping DURING server outage" ping_ok $B "$A4" 5

log "backup/restore drill"
mkdir -p "$WORK/backup"
cp "$WORK/server/server.db"* "$WORK/backup/" 2>/dev/null
rm -rf "$WORK/server"
mkdir -p "$WORK/server"
cp "$WORK/backup/"* "$WORK/server/"
start_server
check "restored server healthz" ns $SRV curl -fsS "http://$UI/healthz"
ns $SRV curl -fsS -c "$WORK/cookies2" -X POST "http://$UI/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
devices_online() {
  for _ in $(seq 1 60); do
    N=$(ns $SRV curl -fsS -b "$WORK/cookies2" "http://$UI/api/devices" 2>/dev/null \
      | grep -o '"online":true' | wc -l)
    [ "$N" = 2 ] && return 0
    sleep 1
  done
  return 1
}
check "both daemons reconnect after restore (no re-enroll)" devices_online
check "a -> b still fine after restore" ping_ok $A "$B4"
NEWKEY_COUNT=$(ns $SRV curl -fsS -b "$WORK/cookies2" "http://$UI/api/setupkeys" 2>/dev/null | grep -o '"key"' | wc -l)
check "setup keys survived the restore" test "$NEWKEY_COUNT" -ge 1

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
