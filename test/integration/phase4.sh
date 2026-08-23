#!/usr/bin/env bash
# Phase 4 exit test: overlay DNS (bare hostnames, Tailscale-style) and
# web-UI-managed access rules enforced live on the data plane.
#
# Flat LAN topology (DNS/ACL semantics are connectivity-independent;
# phases 2/3 cover NAT). Each client namespace gets a private
# resolv.conf via /etc/netns/<ns>/ so the daemon's DNS configuration is
# observable and isolated.
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase4.XXXXXX)"
NET=om-p4-net; SRV=om-p4-srv; A=om-p4-a; B=om-p4-b
SRV_IP=10.220.0.1; A_IP=10.220.0.2; B_IP=10.220.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=phase4-test-password
PASS=0; FAIL=0

log() { echo "[phase4] $*"; }
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
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  rm -rf /etc/netns/$A /etc/netns/$B
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase4] logs kept in $WORK"
    tail -n 25 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh om-lab-udpecho; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build' and 'go build -o bin/om-lab-udpecho ./test/lab/udpecho'"; exit 1; }
done

log "topology: 3 namespaces on one bridge, private resolv.conf for clients"
for n in $A $B; do
  mkdir -p /etc/netns/$n
  printf 'nameserver 192.0.2.99\n' > /etc/netns/$n/resolv.conf # dummy upstream
done
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p4v$i" type veth peer name "p4b$i"
  ip link set "p4v$i" netns "$n"
  ip link set "p4b$i" netns "$NET"
  ns $NET ip link set "p4b$i" master br0
  ns $NET ip link set "p4b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p4v$i"
  ns "$n" ip link set "p4v$i" up
  i=$((i+1))
done

log "control plane (DNS + relay on by default)"
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

log "daemons join"
for side in a b; do
  NSN=$([ "$side" = a ] && echo $A || echo $B)
  ns $NSN env OM_HOSTNAME="node-$side" "$BIN/overmeshd" \
    -state-dir "$WORK/$side" -socket "$WORK/$side.sock" -wg-mode userspace \
    >"$WORK/$side.log" 2>&1 &
  for _ in $(seq 1 50); do [ -S "$WORK/$side.sock" ] && break; sleep 0.2; done
  ns $NSN "$BIN/overmesh" up -socket "$WORK/$side.sock" -server "$GRPC" -key "$KEY"
done

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
check "a -> b connectivity (by IP)" ping_ok $A "$B4"

log "overlay DNS: FQDN and bare hostnames (the Tailscale experience)"
resolves() { # <ns> <name> <expect-ipv4>
  # ahostsv4 forces A lookups; plain `getent hosts` prefers the AAAA
  # record and would print the overlay IPv6 instead.
  ns "$1" getent ahostsv4 "$2" 2>/dev/null | grep -q "$3"
}
retry_resolves() {
  for _ in $(seq 1 15); do
    resolves "$1" "$2" "$3" && return 0
    sleep 1
  done
  return 1
}
check "node-b.default.mesh resolves on a" retry_resolves $A "node-b.default.mesh" "$B4"
check "BARE name 'node-b' resolves on a" retry_resolves $A "node-b" "$B4"
check "BARE name 'node-a' resolves on b" retry_resolves $B "node-a" "$A4"
check "resolv.conf carries the overmesh block" \
  bash -c "ip netns exec $A cat /etc/resolv.conf | grep -q 'BEGIN overmesh dns'"
# -4: without it ping prefers the AAAA record, and overlay IPv6 isn't
# what this check is about (and isn't configured on every CI runner).
bare_ping_ok() {
  for _ in $(seq 1 15); do
    ns $A ping -4 -c1 -W2 node-b >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "ping by bare hostname" bare_ping_ok

log "access rules: deny tcp/22 via the admin API, ping must keep working"
ns $B "$BIN/om-lab-udpecho" -tcp-listen "$B4:22" >"$WORK/hello.log" 2>&1 &
tcp_open() { # retry: listener startup and path settling both race us
  for _ in $(seq 1 10); do
    ns $A "$BIN/om-lab-udpecho" -tcp-probe "$B4:22" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "tcp/22 reachable before any rules" tcp_open

RULES='{"rules":[
  {"action":"deny","src_ids":[],"dst_ids":[],"protocol":"tcp","ports":["22"]},
  {"action":"allow","src_ids":[],"dst_ids":[],"protocol":"","ports":[]}
]}'
check "PUT /api/acl accepts the rule set" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X PUT 'http://$HTTP/api/acl' -d '$RULES'"
sleep 2 # netmap push + filter apply

tcp_blocked() {
  for _ in $(seq 1 10); do
    if ! ns $A "$BIN/om-lab-udpecho" -tcp-probe "$B4:22" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}
check "tcp/22 now blocked" tcp_blocked
check "ping still allowed while ssh is denied" ping_ok $A "$B4" 5
check "dry-run API agrees: tcp/22 blocked" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X POST 'http://$HTTP/api/acl/check' \
   -d '{\"src_id\":1,\"dst_id\":2,\"protocol\":\"tcp\",\"port\":22}' | grep -q '\"allowed\":false'"
check "dry-run API agrees: icmp allowed" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X POST 'http://$HTTP/api/acl/check' \
   -d '{\"src_id\":1,\"dst_id\":2,\"protocol\":\"icmp\",\"port\":0}' | grep -q '\"allowed\":true'"

log "clearing rules restores access live"
check "PUT /api/acl []" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X PUT 'http://$HTTP/api/acl' -d '{\"rules\":[]}'"
tcp_open_again() {
  for _ in $(seq 1 10); do
    ns $A "$BIN/om-lab-udpecho" -tcp-probe "$B4:22" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "tcp/22 reachable again" tcp_open_again

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
