#!/usr/bin/env bash
# Phase 2 exit test: NAT holepunching over the lab topology.
#
# The control plane (with embedded STUN) runs on the simulated internet;
# each client sits behind its own NAT gateway. Expectations:
#   cone      <-> cone       direct path, overlay pings pass
#   any symmetric side       clean "no path" (relay arrives in Phase 3)
# The lab's cone NAT is netfilter MASQUERADE = PORT-restricted filtering,
# and port-restricted <-> symmetric cannot holepunch (the symmetric side's
# per-destination random port is unknowable in advance) — that combination
# is honest relay territory, like symmetric <-> symmetric.
# Plus roaming: re-addressing a client's LAN recovers connectivity.
#
# Usage: sudo test/integration/phase2.sh <nat_a> <nat_b>   (cone|symmetric)
set -euo pipefail

# The lab is self-contained: never route its traffic through host proxies
# (gRPC and curl both honor these).
export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

NAT_A="${1:-cone}"; NAT_B="${2:-cone}"
EXPECT="none"
[ "$NAT_A" = cone ] && [ "$NAT_B" = cone ] && EXPECT="direct"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase2.XXXXXX)"
LAB="$REPO_ROOT/test/lab/lab.sh"
# Lab names/addresses (from test/lab/lab.sh).
INET=om-inet; CLA=om-cl-a; CLB=om-cl-b
INET_IP=192.0.2.1
HTTP="$INET_IP:8080"; GRPC="$INET_IP:41641"
ADMIN_PW=phase2-test-password
PASS=0; FAIL=0

log() { echo "[phase2] $*"; }
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
    echo "[phase2] logs kept in $WORK"
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

log "control plane on the simulated internet (STUN embedded)"
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

path_of() { # <ns> <socket> -> current path value of the single peer
  ns "$1" "$BIN/overmesh" status -socket "$2" -json 2>/dev/null \
    | sed -n 's/.*"path": *"\([a-z]*\)".*/\1/p' | head -1
}
wait_path() { # <ns> <socket> <want> [tries]
  local tries="${4:-40}"
  for _ in $(seq 1 "$tries"); do
    [ "$(path_of "$1" "$2")" = "$3" ] && return 0
    sleep 1
  done
  return 1
}
ping_ok() { # <ns> <addr> [tries]
  for _ in $(seq 1 "${3:-10}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

if [ "$EXPECT" = direct ]; then
  log "expecting holepunched direct paths"
  check "node-a reaches direct path" wait_path $CLA "$WORK/a.sock" direct
  check "node-b reaches direct path" wait_path $CLB "$WORK/b.sock" direct
  check "a -> b ping over overlay" ping_ok $CLA "$B4"
  check "b -> a ping over overlay" ping_ok $CLB "$A4"

  log "roaming: re-address node-a's LAN and expect recovery"
  # Delete-then-add (like a DHCP renewal): the fresh address re-creates
  # the connected route; then restore the default route it took along.
  ns $CLA ip addr del 10.101.0.2/24 dev la0
  ns $CLA ip addr add 10.101.0.77/24 dev la0
  ns $CLA ip route replace default via 10.101.0.1
  # Recovery budget: keepalive detects the dead control connection in
  # ~15s, then re-register + re-signal + re-punch.
  check "a -> b ping after re-address" ping_ok $CLA "$B4" 45
else
  log "expecting clean no-path (symmetric NAT involved; relay is Phase 3)"
  # Negotiation must settle to 'none' (ICE fails) without crashing.
  check "node-a settles to no direct path" wait_path $CLA "$WORK/a.sock" none 90
  check "a -> b overlay ping fails (no path)" bash -c "! ip netns exec $CLA ping -c1 -W2 $B4"
  check "daemon a still healthy" ns $CLA "$BIN/overmesh" status -socket "$WORK/a.sock"
  check "daemon b still healthy" ns $CLB "$BIN/overmesh" status -socket "$WORK/b.sock"
  check "control plane still healthy" ns $INET curl -fsS "http://$HTTP/healthz"
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
