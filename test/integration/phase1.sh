#!/usr/bin/env bash
# Phase 1 exit test: on one simulated LAN (three network namespaces),
# a control plane + two nodes register via a setup key created through
# the admin API, receive netmaps, program WireGuard, and ping each other
# over their overlay addresses (v4 and v6). Also asserts the admin API
# sees both devices online.
#
#   [om-i1-srv 10.210.0.1]---br0---[om-i1-a 10.210.0.2]
#                            \-----[om-i1-b 10.210.0.3]
#
# Usage: sudo test/integration/phase1.sh [kernel|userspace|auto]
set -euo pipefail

# Self-contained lab: never route its traffic through host proxies.
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

MODE="${1:-auto}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase1.XXXXXX)"
NET=om-i1-net; SRV=om-i1-srv; A=om-i1-a; B=om-i1-b
SRV_IP=10.210.0.1; A_IP=10.210.0.2; B_IP=10.210.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=phase1-test-password
PASS=0; FAIL=0

log() { echo "[phase1] $*"; }
ns()  { ip netns exec "$@"; }

check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"; PASS=$((PASS+1))
  else
    echo "  FAIL  $desc"; FAIL=$((FAIL+1))
  fi
}

cleanup() {
  set +e
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build' first"; exit 1; }
done

log "topology: 3 namespaces on one bridge"
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p1v$i" type veth peer name "p1b$i"
  ip link set "p1v$i" netns "$n"
  ip link set "p1b$i" netns "$NET"
  ns $NET ip link set "p1b$i" master br0
  ns $NET ip link set "p1b$i" up
  ns "$n" sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 2>/dev/null || true
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p1v$i"
  ns "$n" ip link set "p1v$i" up
  i=$((i+1))
done

log "starting control plane"
ns $SRV "$BIN/overmesh-server" -http "$HTTP" -grpc "$GRPC" \
  -state-dir "$WORK/server" -admin-password "$ADMIN_PW" \
  >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  ns $SRV curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
check "server healthz" ns $SRV curl -fsS "http://$HTTP/healthz"

log "admin API: login + create setup key"
ns $SRV curl -fsS -c "$WORK/cookies" -X POST "http://$HTTP/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(ns $SRV curl -fsS -b "$WORK/cookies" -X POST "http://$HTTP/api/setupkeys" \
  -d '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$KEY" ] || { echo "no setup key from API"; exit 1; }
log "setup key: ${KEY:0:12}..."

log "starting daemons (wg-mode=$MODE) and joining"
for side in a b; do
  NSN=$([ "$side" = a ] && echo $A || echo $B)
  ns $NSN env OM_HOSTNAME="node-$side" "$BIN/overmeshd" \
    -state-dir "$WORK/$side" -socket "$WORK/$side.sock" -wg-mode "$MODE" \
    >"$WORK/$side.log" 2>&1 &
  for _ in $(seq 1 50); do [ -S "$WORK/$side.sock" ] && break; sleep 0.2; done
  ns $NSN "$BIN/overmesh" up -socket "$WORK/$side.sock" -server "$GRPC" -key "$KEY"
done

log "waiting for both nodes to see each other online"
wait_peer_online() { # <ns> <socket>
  for _ in $(seq 1 50); do
    if ns "$1" "$BIN/overmesh" status -socket "$2" -json 2>/dev/null \
        | grep -q '"online": *true'; then return 0; fi
    sleep 0.3
  done
  return 1
}
check "node-a sees a peer online" wait_peer_online $A "$WORK/a.sock"
check "node-b sees a peer online" wait_peer_online $B "$WORK/b.sock"

get_ip() { # <ns> <socket> <ipv4|ipv6>
  ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n "s/.*\"$3\": *\"\([^\"]*\)\".*/\1/p" | head -1
}
A4=$(get_ip $A "$WORK/a.sock" ipv4); A6=$(get_ip $A "$WORK/a.sock" ipv6)
B4=$(get_ip $B "$WORK/b.sock" ipv4); B6=$(get_ip $B "$WORK/b.sock" ipv6)
log "overlay addresses: a=$A4/$A6  b=$B4/$B6"

log "the exit test: ping over the overlay"
# First contact includes a WireGuard handshake, and with Phase 1's naive
# path handling convergence can take up to one keepalive cycle (25s) on
# some kernels. Allow ~40s; Phase 2's magicsock replaces this with active
# path management and tightens the budget.
ping_ok() { # <ns> <addr> [-6]
  local n="$1" addr="$2" v="${3:-}"
  for _ in $(seq 1 13); do
    # shellcheck disable=SC2086
    ns "$n" ping $v -c1 -W2 "$addr" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "a -> b over overlay IPv4 ($B4)" ping_ok $A "$B4"
check "b -> a over overlay IPv4 ($A4)" ping_ok $B "$A4"
# IPv6 only where the kernel has it (some containers boot ipv6.disable=1;
# the engine degrades to IPv4-only there, and so does this test).
if ns $A test -d /proc/sys/net/ipv6; then
  check "a -> b over overlay IPv6 ($B6)" ping_ok $A "$B6" -6
  check "b -> a over overlay IPv6 ($A6)" ping_ok $B "$A6" -6
else
  echo "  SKIP  IPv6 checks (kernel has IPv6 disabled)"
fi

log "admin API sees both devices online"
devices_online() {
  local out
  out=$(ns $SRV curl -fsS -b "$WORK/cookies" "http://$HTTP/api/devices")
  [ "$(grep -o '"online":true' <<<"$out" | wc -l)" -eq 2 ]
}
check "GET /api/devices reports 2 online devices" devices_online

log "overmesh down tears the tunnel down"
ns $A "$BIN/overmesh" down -socket "$WORK/a.sock"
check "a -> b fails after down" bash -c "! ip netns exec $A ping -c1 -W2 $B4"

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures) — logs in $WORK (kept)"
  tail -n 20 "$WORK"/*.log || true
  if command -v wg >/dev/null; then
    for side in "$A:a" "$B:b"; do
      echo "--- wg show in ${side##*:}:"; ns "${side%%:*}" wg show 2>&1 || true
    done
  fi
  for side in "$A:a" "$B:b"; do
    echo "--- links in ${side##*:}:"; ns "${side%%:*}" ip -s link show 2>&1 | head -20 || true
  done
  trap - EXIT
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null || true; done
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  exit 1
fi
log "ALL $PASS CHECKS PASSED (wg-mode=$MODE)"
