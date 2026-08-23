#!/usr/bin/env bash
# Phase 3 exit test: the OMR relay guarantees connectivity and catches
# falls from direct paths.
#
# Topology: control plane (embedded STUN + relay) on the simulated
# internet; one daemon behind each NAT gateway. Expectations:
#   both cone            direct path (relay bootstraps, ICE upgrades),
#                        then: block UDP -> falls back to relay, pings
#                        keep working
#   any symmetric side   relay path, overlay pings pass (this was the
#                        clean-failure case before Phase 3)
#
# Usage: sudo test/integration/phase3.sh <nat_a> <nat_b>   (cone|symmetric)
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

NAT_A="${1:-symmetric}"; NAT_B="${2:-symmetric}"
EXPECT="relay"
[ "$NAT_A" = cone ] && [ "$NAT_B" = cone ] && EXPECT="direct"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase3.XXXXXX)"
LAB="$REPO_ROOT/test/lab/lab.sh"
INET=om-inet; CLA=om-cl-a; CLB=om-cl-b; NATA=om-nat-a; NATB=om-nat-b
INET_IP=192.0.2.1
HTTP="$INET_IP:8080"; GRPC="$INET_IP:41641"
ADMIN_PW=phase3-test-password
PASS=0; FAIL=0

log() { echo "[phase3] $*"; }
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
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  "$LAB" down >/dev/null 2>&1
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase3] logs kept in $WORK"
    tail -n 25 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build' first"; exit 1; }
done

log "lab up: nat-a=$NAT_A nat-b=$NAT_B (expect: $EXPECT)"
"$LAB" down >/dev/null 2>&1 || true
"$LAB" up --nat-a "$NAT_A" --nat-b "$NAT_B" >/dev/null

log "control plane with embedded STUN + relay"
ns $INET "$BIN/overmesh-server" -http "$HTTP" -grpc "$GRPC" -stun "$INET_IP:3478" \
  -state-dir "$WORK/server" -admin-password "$ADMIN_PW" \
  >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  ns $INET curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
check "server healthz" ns $INET curl -fsS "http://$HTTP/healthz"

ns $INET curl -fsS -c "$WORK/cookies" -X POST "http://$HTTP/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(ns $INET curl -fsS -b "$WORK/cookies" -X POST "http://$HTTP/api/setupkeys" \
  -d '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$KEY" ] || { echo "no setup key from API"; exit 1; }

log "daemons join from behind their NATs"
for side in a b; do
  NSN=$([ "$side" = a ] && echo $CLA || echo $CLB)
  ns $NSN env OM_HOSTNAME="node-$side" "$BIN/overmeshd" \
    -state-dir "$WORK/$side" -socket "$WORK/$side.sock" -wg-mode userspace \
    >"$WORK/$side.log" 2>&1 &
  for _ in $(seq 1 50); do [ -S "$WORK/$side.sock" ] && break; sleep 0.2; done
  ns $NSN "$BIN/overmesh" up -socket "$WORK/$side.sock" -server "$GRPC" -key "$KEY"
done

get_ip() { ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n "s/.*\"$3\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
A4=$(get_ip $CLA "$WORK/a.sock" ipv4); B4=$(get_ip $CLB "$WORK/b.sock" ipv4)
log "overlay: a=$A4 b=$B4"

path_of() {
  ns "$1" "$BIN/overmesh" status -socket "$2" -json 2>/dev/null \
    | sed -n 's/.*"path": *"\([a-z]*\)".*/\1/p' | head -1
}
wait_path() { # <ns> <socket> <want> [tries]
  # Default budget covers one full ICE retry cycle: on a loaded CI
  # runner the first attempt can time out and the retry lands ~90s in.
  for _ in $(seq 1 "${4:-120}"); do
    [ "$(path_of "$1" "$2")" = "$3" ] && return 0
    sleep 1
  done
  return 1
}
ping_ok() { # <ns> <addr> [tries]
  for _ in $(seq 1 "${3:-15}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

if [ "$EXPECT" = relay ]; then
  log "expecting relayed connectivity (this failed cleanly before Phase 3)"
  check "node-a path becomes relay" wait_path $CLA "$WORK/a.sock" relay
  check "node-b path becomes relay" wait_path $CLB "$WORK/b.sock" relay
  check "a -> b ping over relay" ping_ok $CLA "$B4"
  check "b -> a ping over relay" ping_ok $CLB "$A4"
else
  log "expecting relay bootstrap then direct upgrade"
  check "a -> b ping works (relay or direct)" ping_ok $CLA "$B4"
  check "node-a upgrades to direct" wait_path $CLA "$WORK/a.sock" direct
  check "node-b upgrades to direct" wait_path $CLB "$WORK/b.sock" direct
  check "a -> b ping still works" ping_ok $CLA "$B4"

  log "failover: blocking all UDP forwarding at both NATs (except STUN port stays irrelevant now)"
  ns $NATA iptables -I FORWARD 1 -p udp -j DROP
  ns $NATB iptables -I FORWARD 1 -p udp -j DROP
  check "node-a falls back to relay" wait_path $CLA "$WORK/a.sock" relay 60
  check "a -> b ping recovers over relay TCP" ping_ok $CLA "$B4" 30
  check "b -> a ping recovers over relay TCP" ping_ok $CLB "$A4" 30
fi

devices_online() {
  for _ in $(seq 1 30); do
    if ns $INET curl -fsS -b "$WORK/cookies" "http://$HTTP/api/devices" 2>/dev/null \
        | grep -o '"online":true' | wc -l | grep -q '^2$'; then return 0; fi
    sleep 1
  done
  return 1
}
check "admin API sees 2 devices online" devices_online

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED (nat-a=$NAT_A nat-b=$NAT_B expect=$EXPECT)"
