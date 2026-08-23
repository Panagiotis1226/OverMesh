#!/usr/bin/env bash
# Phase 6 exit test: OverDrop file transfer.
#
#   - send a file A -> B, checksum-verified, listed by `overmesh inbox`
#   - kill the sender mid-transfer, then resume to completion
#   - access rules (deny tcp/41645) block drops, live
#   - a transfer completes over the TCP relay path (UDP blackout)
#
# Flat LAN topology; the relay part just blocks WireGuard's UDP port.
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-phase6.XXXXXX)"
NET=om-p6-net; SRV=om-p6-srv; A=om-p6-a; B=om-p6-b
SRV_IP=10.250.0.1; A_IP=10.250.0.2; B_IP=10.250.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=phase6-test-password
PASS=0; FAIL=0

log() { echo "[phase6] $*"; }
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
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  if [ "$OK" = 1 ]; then
    rm -rf "$WORK"
  else
    echo "[phase6] logs kept in $WORK"
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
  ip link add "p6v$i" type veth peer name "p6b$i"
  ip link set "p6v$i" netns "$n"
  ip link set "p6b$i" netns "$NET"
  ns $NET ip link set "p6b$i" master br0
  ns $NET ip link set "p6b$i" up
  ns "$n" ip link set lo up
  ns "$n" ip addr add "$addr/24" dev "p6v$i"
  ns "$n" ip link set "p6v$i" up
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
B4=$(get_ip $B "$WORK/b.sock" ipv4)
INBOX_B="$WORK/b/overdrop"

ping_ok() {
  for _ in $(seq 1 "${3:-15}"); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "a -> b connectivity" ping_ok $A "$B4"

log "basic drop: small file A -> B, checksum + inbox listing"
head -c 3145728 /dev/urandom > "$WORK/notes.pdf" # 3 MiB
SUM_SMALL=$(sha256sum "$WORK/notes.pdf" | cut -d' ' -f1)
drop_ok() { # <file> [tries] — the receiver starts with the first netmap
  for _ in $(seq 1 "${2:-10}"); do
    ns $A "$BIN/overmesh" drop -socket "$WORK/a.sock" "$1" node-b >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}
check "overmesh drop delivers the file" drop_ok "$WORK/notes.pdf"
check "received file has the right checksum" bash -c \
  "sha256sum '$INBOX_B/node-a/notes.pdf' | grep -q $SUM_SMALL"
check "overmesh inbox lists it on B" bash -c \
  "ip netns exec $B '$BIN/overmesh' inbox -socket '$WORK/b.sock' | grep -q notes.pdf"

log "interrupt + resume: kill the sender mid-transfer of a 400 MiB file"
head -c 419430400 /dev/urandom > "$WORK/big.iso"
SUM_BIG=$(sha256sum "$WORK/big.iso" | cut -d' ' -f1)
timeout -s KILL 1 ip netns exec $A "$BIN/overmesh" drop -socket "$WORK/a.sock" \
  "$WORK/big.iso" node-b >/dev/null 2>&1 || true
check "partial .part staged on B after the kill" bash -c \
  "ls '$INBOX_B/node-a/' | grep -q 'big.iso.*.part'"
check_not "final file NOT present yet" test -f "$INBOX_B/node-a/big.iso"
PART_SIZE=$(stat -c %s "$INBOX_B"/node-a/big.iso.*.part 2>/dev/null || echo 0)
log "  staged $PART_SIZE bytes before the kill"
check "resumed transfer completes" drop_ok "$WORK/big.iso" 3
check "resumed file checksum matches" bash -c \
  "sha256sum '$INBOX_B/node-a/big.iso' | grep -q $SUM_BIG"
check_not ".part cleaned up after completion" bash -c \
  "ls '$INBOX_B/node-a/' | grep -q '.part$'"

log "access rules: deny tcp/41645 blocks OverDrop, live"
RULES='{"rules":[
  {"action":"deny","src_ids":[],"dst_ids":[],"protocol":"tcp","ports":["41645"]},
  {"action":"allow","src_ids":[],"dst_ids":[],"protocol":"","ports":[]}
]}'
check "PUT /api/acl deny drop port" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X PUT 'http://$HTTP/api/acl' -d '$RULES'"
sleep 2
drop_blocked() {
  for _ in $(seq 1 8); do
    if ! ns $A timeout 10 "$BIN/overmesh" drop -socket "$WORK/a.sock" "$WORK/notes.pdf" node-b >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  return 1
}
check "drop is blocked by the rule" drop_blocked
check "ping still works while drops are denied" ping_ok $A "$B4" 5
check "clearing rules" bash -c \
  "ip netns exec $SRV curl -fsS -b '$WORK/cookies' -X PUT 'http://$HTTP/api/acl' -d '{\"rules\":[]}'"
check "drop works again after clearing" drop_ok "$WORK/notes.pdf"

log "relay path: blackout UDP between the peers, transfer over relay TCP"
ns $A iptables -I OUTPUT 1 -p udp --dport 41642 -j DROP
ns $A iptables -I INPUT 1 -p udp --sport 41642 -j DROP
relay_path() {
  for _ in $(seq 1 60); do
    if ns $A "$BIN/overmesh" status -socket "$WORK/a.sock" -json 2>/dev/null \
        | grep -q '"path": *"relay"'; then return 0; fi
    sleep 1
  done
  return 1
}
check "path falls back to relay" relay_path
head -c 8388608 /dev/urandom > "$WORK/over-relay.bin" # 8 MiB
SUM_RELAY=$(sha256sum "$WORK/over-relay.bin" | cut -d' ' -f1)
check "drop succeeds over the relay" drop_ok "$WORK/over-relay.bin" 5
check "relayed file checksum matches" bash -c \
  "sha256sum '$INBOX_B/node-a/over-relay.bin' | grep -q $SUM_RELAY"

if [ $FAIL -gt 0 ]; then
  log "FAILED ($FAIL failures)"
  exit 1
fi
OK=1
log "ALL $PASS CHECKS PASSED"
