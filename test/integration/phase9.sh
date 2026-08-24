#!/usr/bin/env bash
# Phase 9 exit test: the mobile core over a platform-provided TUN fd.
#
# om-mobileharness stands in for the iOS packet-tunnel app: it opens
# /dev/net/tun itself, hands the fd to mobilecore, and
# programs addresses/routes from the OnNetMap callback — exactly the
# platform contract, minus Swift. Against it, a stock overmeshd peer:
#
#   - the harness joins the mesh over the fd-backed engine
#   - ping both ways (harness <-> stock daemon)
#   - bare-hostname DNS served by the in-tunnel meshdns on the
#     harness's own overlay IP
#   - OverDrop delivery INTO the mobile inbox
#   - UDP blackout -> the harness's peer path degrades to relay
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase9.XXXXXX)"
NET=om-p9-net; SRV=om-p9-srv; A=om-p9-a; M=om-p9-m
SRV_IP=10.251.0.1; A_IP=10.251.0.2; M_IP=10.251.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=phase9-test-password
STATUS="$WORK/m-status.json"
PASS=0; FAIL=0

log() { echo "[phase9] $*"; }
ns()  { ip netns exec "$@"; }
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"; PASS=$((PASS+1))
  else
    echo "  FAIL  $desc"; FAIL=$((FAIL+1))
  fi
}

OK=0
cleanup() {
  set +e
  pkill -f "socket $WORK" 2>/dev/null
  [ -n "${HARNESS_PID:-}" ] && kill "$HARNESS_PID" 2>/dev/null
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  for n in $SRV $A $M $NET; do ip netns del "$n" 2>/dev/null; done
  rm -rf "/etc/netns/$M"
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase9] logs kept in $WORK"
    tail -n 30 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh om-mobileharness; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build' and 'go build -o bin/om-mobileharness ./test/mobileharness'"; exit 1; }
done

log "topology + control plane"
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $M
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$M:$M_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p9v$i" type veth peer name "p9b$i"
  ip link set "p9v$i" netns "$n"
  ip link set "p9b$i" netns "$NET"
  ns $NET ip link set "p9b$i" master br0
  ns $NET ip link set "p9b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p9v$i"
  ns "$n" ip link set "p9v$i" up
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

ns $SRV curl -fsS -c "$WORK/cookies" -X POST "http://$HTTP/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(ns $SRV curl -fsS -b "$WORK/cookies" -X POST "http://$HTTP/api/setupkeys" \
  -d '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$KEY" ] || { echo "no setup key"; exit 1; }

log "stock daemon (node-a) joins"
ns $A env OM_HOSTNAME=node-a "$BIN/overmeshd" \
  -state-dir "$WORK/a" -socket "$WORK/a.sock" -wg-mode userspace \
  >"$WORK/a.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$WORK/a.sock" ] && break; sleep 0.2; done
ns $A "$BIN/overmesh" up -socket "$WORK/a.sock" -server "$GRPC" -key "$KEY"
A4=$(ns $A "$BIN/overmesh" status -socket "$WORK/a.sock" -json \
  | sed -n 's/.*"ipv4": *"\([^"]*\)".*/\1/p' | head -1)
[ -n "$A4" ] || { echo "node-a has no overlay ip"; exit 1; }

log "mobile harness joins over a real TUN fd"
ns $M "$BIN/om-mobileharness" -state-dir "$WORK/m-state" -server "$GRPC" \
  -key "$KEY" -hostname mobile-sim -tun omtun9 -status-file "$STATUS" \
  >"$WORK/m.log" 2>&1 &
HARNESS_PID=$!

# First occurrence wins: the self "ipv4" (top-level, keys sorted)
# precedes the per-peer ones inside "peers". Tolerates the status file
# not existing yet (pipefail would otherwise abort the whole script on
# the first pre-startup poll).
status_field() { { grep -o "\"$1\":\"[^\"]*\"" "$STATUS" 2>/dev/null || true; } | head -1 | cut -d'"' -f4; }
M4=""
for _ in $(seq 1 60); do
  M4=$(status_field ipv4)
  [ -n "$M4" ] && break
  sleep 1
done
check "harness got an overlay IPv4 ($M4)" test -n "$M4"
check "harness reports running" bash -c "grep -q '\"running\":true' '$STATUS'"

ping_ok() {
  for _ in $(seq 1 "${3:-30}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
log "connectivity both ways"
check "mobile -> node-a ping" ping_ok $M "$A4"
check "node-a -> mobile ping" ping_ok $A "$M4"

log "bare-hostname DNS via the in-tunnel meshdns"
# On a phone the OS points DNS at the tunnel per OnNetMap's dns_server;
# here the netns resolv.conf plays that role.
mkdir -p "/etc/netns/$M"
printf 'nameserver %s\nsearch default.mesh\n' "$M4" > "/etc/netns/$M/resolv.conf"
resolves() { # ahostsv4: plain `getent hosts` prefers the AAAA record
  ns $M getent ahostsv4 "$1" 2>/dev/null | grep -q "$2"
}
retry_resolves() {
  for _ in $(seq 1 20); do
    resolves "$1" "$2" && return 0
    sleep 1
  done
  return 1
}
check "FQDN node-a.default.mesh resolves on mobile" retry_resolves "node-a.default.mesh" "$A4"
check "BARE name 'node-a' resolves on mobile" retry_resolves "node-a" "$A4"
dns_ping_ok() {
  for _ in $(seq 1 10); do
    ns $M ping -4 -c1 -W2 node-a >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "mobile pings 'node-a' by bare name" dns_ping_ok

log "OverDrop into the mobile inbox"
head -c 5242880 /dev/urandom > "$WORK/clip.mov" # 5 MiB
SUM=$(sha256sum "$WORK/clip.mov" | cut -d' ' -f1)
drop_ok() {
  for _ in $(seq 1 10); do
    ns $A "$BIN/overmesh" drop -socket "$WORK/a.sock" "$WORK/clip.mov" mobile-sim >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "node-a drops a file to mobile-sim" drop_ok
check "mobile inbox file checksum matches" bash -c \
  "sha256sum '$WORK/m-state/overdrop/node-a/clip.mov' | grep -q $SUM"

log "relay fallback: UDP blackout on the mobile side"
ns $M iptables -I OUTPUT 1 -p udp --dport 41642 -j DROP
ns $M iptables -I INPUT 1 -p udp --sport 41642 -j DROP
relay_path() {
  for _ in $(seq 1 60); do
    grep -q '"path":"relay"' "$STATUS" 2>/dev/null && return 0
    sleep 1
  done
  return 1
}
check "harness path degrades to relay" relay_path
check "mobile -> node-a ping over relay" ping_ok $M "$A4" 30

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
