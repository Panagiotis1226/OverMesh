#!/usr/bin/env bash
# Phase 5 exit test: subnet routers and exit nodes, approval-gated in the
# admin API (the web UI drives the same endpoint), with loop-free
# policy routing on the exit-node client.
#
# Topology:
#
#   [ A ]────control LAN────[ B ]────lan0────[ LANH ]   192.168.77.0/24
#   client   10.230.0.0/24  router└──wan0────[ INET ]   203.0.113.0/24
#            [ SRV ] control plane
#
# B advertises 192.168.77.0/24 (subnet router) and the default routes
# (exit node). A asks to use B as its exit node. Nothing works until the
# admin approves each route; everything works live afterwards; revoking
# cuts it off again.
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase5.XXXXXX)"
NET=om-p5-net; SRV=om-p5-srv; A=om-p5-a; B=om-p5-b; LANH=om-p5-lan; INET=om-p5-inet
SRV_IP=10.230.0.1; A_IP=10.230.0.2; B_IP=10.230.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
LAN_NET=192.168.77.0/24; LAN_GW=192.168.77.1; LAN_HOST=192.168.77.2
WAN_B=203.0.113.2; WAN_INET=203.0.113.1
ADMIN_PW=phase5-test-password
PASS=0; FAIL=0

log() { echo "[phase5] $*"; }
ns()  { ip netns exec "$@"; }
check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"; PASS=$((PASS+1))
  else
    echo "  FAIL  $desc"; FAIL=$((FAIL+1))
  fi
}
check_not() { # inverted: succeed when the command FAILS
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
  for n in $SRV $A $B $LANH $INET $NET; do ip netns del "$n" 2>/dev/null; done
  rm -rf /etc/netns/$A /etc/netns/$B
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase5] logs kept in $WORK"
    tail -n 30 "$WORK"/*.log 2>/dev/null || true
  fi
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
for b in overmesh-server overmeshd overmesh om-lab-udpecho; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build' and 'go build -o bin/om-lab-udpecho ./test/lab/udpecho'"; exit 1; }
done

log "topology up"
for n in $A $B; do
  mkdir -p /etc/netns/$n
  printf 'nameserver 192.0.2.99\n' > /etc/netns/$n/resolv.conf
done
ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
ip netns add $LANH; ip netns add $INET

# Control LAN: SRV, A, B on one bridge.
ns $NET ip link add br0 type bridge
ns $NET ip link set br0 up
i=1
for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
  n="${pair%%:*}"; addr="${pair##*:}"
  ip link add "p5v$i" type veth peer name "p5b$i"
  ip link set "p5v$i" netns "$n"
  ip link set "p5b$i" netns "$NET"
  ns $NET ip link set "p5b$i" master br0
  ns $NET ip link set "p5b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p5v$i"
  ns "$n" ip link set "p5v$i" up
  i=$((i+1))
done

# B's LAN segment (subnet-router target).
ip link add p5lan0 type veth peer name p5lan1
ip link set p5lan0 netns $B; ip link set p5lan1 netns $LANH
ns $B ip addr add $LAN_GW/24 dev p5lan0
ns $B ip link set p5lan0 up
ns $LANH ip link set lo up
ns $LANH ip addr add $LAN_HOST/24 dev p5lan1
ns $LANH ip link set p5lan1 up
# LANH deliberately has NO route to the overlay: replies only work
# because the router masquerades.

# B's WAN segment (fake internet) + default route.
ip link add p5wan0 type veth peer name p5wan1
ip link set p5wan0 netns $B; ip link set p5wan1 netns $INET
ns $B ip addr add $WAN_B/24 dev p5wan0
ns $B ip link set p5wan0 up
ns $INET ip link set lo up
ns $INET ip addr add $WAN_INET/24 dev p5wan1
ns $INET ip link set p5wan1 up
ns $B ip route add default via $WAN_INET
# A has NO route to 203.0.113.0/24 — only an exit node can get it there.

log "fake internet services on $WAN_INET"
ns $INET "$BIN/om-lab-udpecho" -listen "$WAN_INET:9999,$WAN_INET:9998" >"$WORK/inet-udp.log" 2>&1 &
ns $INET "$BIN/om-lab-udpecho" -tcp-listen "$WAN_INET:80" >"$WORK/inet-tcp.log" 2>&1 &

log "control plane"
ns $SRV "$BIN/overmesh-server" -http "$HTTP" -grpc "$GRPC" -stun "$SRV_IP:3478" \
  -state-dir "$WORK/server" -admin-password "$ADMIN_PW" \
  >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  ns $SRV curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
check "server healthz" ns $SRV curl -fsS "http://$HTTP/healthz"

api() { # <method> <path> [data]
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    ns $SRV curl -fsS -b "$WORK/cookies" -X "$m" "http://$HTTP$p" -d "$d"
  else
    ns $SRV curl -fsS -b "$WORK/cookies" -X "$m" "http://$HTTP$p"
  fi
}
ns $SRV curl -fsS -c "$WORK/cookies" -X POST "http://$HTTP/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(api POST /api/setupkeys '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')
[ -n "$KEY" ] || { echo "no setup key"; exit 1; }

log "daemons join: A plain client (+wants exit via node-b), B advertises routes"
ns $B env OM_HOSTNAME=node-b "$BIN/overmeshd" \
  -state-dir "$WORK/b" -socket "$WORK/b.sock" -wg-mode userspace \
  >"$WORK/b.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$WORK/b.sock" ] && break; sleep 0.2; done
ns $B "$BIN/overmesh" up -socket "$WORK/b.sock" -server "$GRPC" -key "$KEY" \
  -advertise-routes "$LAN_NET" -advertise-exit-node

ns $A env OM_HOSTNAME=node-a "$BIN/overmeshd" \
  -state-dir "$WORK/a" -socket "$WORK/a.sock" -wg-mode userspace \
  >"$WORK/a.log" 2>&1 &
for _ in $(seq 1 50); do [ -S "$WORK/a.sock" ] && break; sleep 0.2; done
ns $A "$BIN/overmesh" up -socket "$WORK/a.sock" -server "$GRPC" -key "$KEY" \
  -exit-node node-b

get_ip() { ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n "s/.*\"$3\": *\"\([^\"]*\)\".*/\1/p" | head -1; }
A4=$(get_ip $A "$WORK/a.sock" ipv4); B4=$(get_ip $B "$WORK/b.sock" ipv4)
log "overlay: a=$A4 b=$B4"

ping_ok() { # <ns> <addr> [tries]
  for _ in $(seq 1 "${3:-15}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "a -> b overlay connectivity" ping_ok $A "$B4"

B_ID=$(api GET /api/devices | python3 -c '
import json,sys
for d in json.load(sys.stdin):
    if d["hostname"] == "node-b": print(d["id"]); break')
[ -n "$B_ID" ] || { echo "node-b not in device list"; exit 1; }

log "before approval: offers exist but must be inert"
check "API lists 3 offered routes for node-b" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' 'http://$HTTP/api/devices' \
   | python3 -c 'import json,sys; d=[x for x in json.load(sys.stdin) if x[\"hostname\"]==\"node-b\"][0]; rs=d[\"routes\"]; assert len(rs)==3 and not any(r[\"approved\"] for r in rs)'"
check_not "LAN host unreachable before approval" ns $A ping -c1 -W2 $LAN_HOST
check_not "internet unreachable before approval" ns $A ping -c1 -W2 $WAN_INET
check "A's exit shows inactive" bash -c \
  "ip netns exec $A '$BIN/overmesh' status -socket '$WORK/a.sock' -json | grep -vq '\"exit_node_active\": *true'"

log "approve the subnet route -> LAN behind node-b opens up"
check "approve 192.168.77.0/24" api PUT "/api/devices/$B_ID/routes" \
  "{\"route\":\"$LAN_NET\",\"approved\":true}"
check "a reaches the LAN host through the router" ping_ok $A $LAN_HOST 20
check_not "internet still blocked (exit not yet approved)" ns $A ping -c1 -W2 $WAN_INET

log "approve the exit-node offer -> A's whole internet goes via node-b"
check "approve 0.0.0.0/0" api PUT "/api/devices/$B_ID/routes" '{"route":"0.0.0.0/0","approved":true}'
check "approve ::/0" api PUT "/api/devices/$B_ID/routes" '{"route":"::/0","approved":true}'
exit_active() {
  for _ in $(seq 1 20); do
    if ns $A "$BIN/overmesh" status -socket "$WORK/a.sock" -json 2>/dev/null \
        | grep -q '"exit_node_active": *true'; then return 0; fi
    sleep 1
  done
  return 1
}
check "A reports exit node active" exit_active
check "a pings the internet via the exit node" ping_ok $A $WAN_INET 20
check "a reaches internet TCP via the exit node" ns $A "$BIN/om-lab-udpecho" -tcp-probe "$WAN_INET:80"
check "internet sees the EXIT NODE's address (masqueraded)" bash -c \
  "ip netns exec $A '$BIN/om-lab-udpecho' -probe '$WAN_INET:9999' | grep -q 'mapped@.*=$WAN_B:'"
check "A's control connection survives exit routing (no loop)" bash -c \
  "ip netns exec $A '$BIN/overmesh' status -socket '$WORK/a.sock' -json | grep -q '\"conn\": *\"connected\"'"
check "a -> b overlay still fine" ping_ok $A "$B4" 5

log "live revocation: pull the exit approval"
check "revoke 0.0.0.0/0" api PUT "/api/devices/$B_ID/routes" '{"route":"0.0.0.0/0","approved":false}'
check "revoke ::/0" api PUT "/api/devices/$B_ID/routes" '{"route":"::/0","approved":false}'
inet_blocked() {
  for _ in $(seq 1 20); do
    if ! ns $A ping -c1 -W2 $WAN_INET >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  return 1
}
check "internet cut off after revocation" inet_blocked
check "LAN route still works (still approved)" ping_ok $A $LAN_HOST 10

log "exit-node off restores plain routing"
check "overmesh exit-node off" ns $A "$BIN/overmesh" exit-node -socket "$WORK/a.sock" off
check "daemon healthy after exit off" ns $A "$BIN/overmesh" status -socket "$WORK/a.sock"

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
