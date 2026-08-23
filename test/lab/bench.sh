#!/usr/bin/env bash
# OverMesh throughput bench: iperf3 across the overlay in three
# configurations on one machine (network namespaces, so numbers measure
# the DATA PLANE cost, not a network):
#
#   userspace  wireguard-go + magicsock (the default engine)
#   kernel     kernel WireGuard (-wg-mode kernel; the exit-node fast path)
#   relay      userspace with UDP blocked -> traffic via the TCP relay
#
# Usage: sudo test/lab/bench.sh [seconds-per-run]   (default 5)
# Requires: iperf3, root.
set -euo pipefail

export NO_PROXY='*' no_proxy='*'
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy || true

DUR="${1:-5}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$REPO_ROOT/bin"
WORK="$(mktemp -d /tmp/om-bench.XXXXXX)"
NET=om-bn-net; SRV=om-bn-srv; A=om-bn-a; B=om-bn-b
SRV_IP=10.240.0.1; A_IP=10.240.0.2; B_IP=10.240.0.3
HTTP="$SRV_IP:8080"; GRPC="$SRV_IP:41641"
ADMIN_PW=bench-password

log() { echo "[bench] $*"; }
ns()  { ip netns exec "$@"; }

cleanup() {
  set +e
  for n in $SRV $A $B $NET; do ip netns del "$n" 2>/dev/null; done
  [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }
command -v iperf3 >/dev/null || { echo "iperf3 not installed"; exit 1; }
for b in overmesh-server overmeshd overmesh; do
  [ -x "$BIN/$b" ] || { echo "missing $BIN/$b — run 'make build'"; exit 1; }
done

topology() {
  ip netns add $NET; ip netns add $SRV; ip netns add $A; ip netns add $B
  ns $NET ip link add br0 type bridge
  ns $NET ip link set br0 up
  local i=1
  for pair in "$SRV:$SRV_IP" "$A:$A_IP" "$B:$B_IP"; do
    local n="${pair%%:*}" addr="${pair##*:}"
    ip link add "bnv$i" type veth peer name "bnb$i"
    ip link set "bnv$i" netns "$n"
    ip link set "bnb$i" netns "$NET"
    ns $NET ip link set "bnb$i" master br0
    ns $NET ip link set "bnb$i" up
    ns "$n" ip link set lo up
    ns "$n" ip addr add "$addr/24" dev "bnv$i"
    ns "$n" ip link set "bnv$i" up
    i=$((i+1))
  done
}

start_daemons() { # <wg-mode>
  local mode="$1"
  for side in a b; do
    local NSN=$([ "$side" = a ] && echo $A || echo $B)
    ns $NSN env OM_HOSTNAME="bench-$side" "$BIN/overmeshd" \
      -state-dir "$WORK/$mode-$side" -socket "$WORK/$side.sock" -wg-mode "$mode" -mtu 1420 \
      >"$WORK/$mode-$side.log" 2>&1 &
    echo $! >> "$WORK/pids"
    for _ in $(seq 1 50); do [ -S "$WORK/$side.sock" ] && break; sleep 0.2; done
    ns $NSN "$BIN/overmesh" up -socket "$WORK/$side.sock" -server "$GRPC" -key "$KEY" >/dev/null
  done
}

stop_daemons() {
  if [ -f "$WORK/pids" ]; then
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$WORK/pids"
    rm -f "$WORK/pids" "$WORK/a.sock" "$WORK/b.sock"
    sleep 1
  fi
}

overlay_ip() { # <ns> <socket>
  ns "$1" "$BIN/overmesh" status -socket "$2" -json | sed -n 's/.*"ipv4": *"\([^"]*\)".*/\1/p' | head -1
}

wait_ping() { # <ns> <addr>
  for _ in $(seq 1 30); do
    ns "$1" ping -c1 -W2 "$2" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

measure() { # <label> <client-ns> <server-ns> <server-ip>
  local label="$1" cns="$2" sns="$3" sip="$4"
  ns "$sns" iperf3 -s -1 -p 5555 >/dev/null 2>&1 &
  sleep 0.5
  local bps
  bps=$(ns "$cns" iperf3 -c "$sip" -p 5555 -t "$DUR" -J 2>/dev/null \
    | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["end"]["sum_received"]["bits_per_second"]))' \
    2>/dev/null || echo 0)
  printf "  %-10s %8.1f Mbit/s\n" "$label" "$(echo "$bps" | awk '{print $1/1e6}')"
  echo "$label $bps" >> "$WORK/results"
}

log "topology + control plane (duration ${DUR}s per run)"
topology
ns $SRV "$BIN/overmesh-server" -http "$HTTP" -grpc "$GRPC" -stun "$SRV_IP:3478" \
  -state-dir "$WORK/server" -admin-password "$ADMIN_PW" >"$WORK/server.log" 2>&1 &
SRV_PID=$!
for _ in $(seq 1 50); do
  ns $SRV curl -fsS "http://$HTTP/healthz" >/dev/null 2>&1 && break
  sleep 0.2
done
ns $SRV curl -fsS -c "$WORK/cookies" -X POST "http://$HTTP/api/login" \
  -d "{\"password\":\"$ADMIN_PW\"}" >/dev/null
KEY=$(ns $SRV curl -fsS -b "$WORK/cookies" -X POST "http://$HTTP/api/setupkeys" \
  -d '{"reusable":true}' | sed -n 's/.*"key":"\(sk-[0-9a-f]*\)".*/\1/p')

echo
echo "OverMesh data-plane throughput ($(nproc) CPUs, MTU 1420, iperf3 ${DUR}s):"

# 1. userspace (the default engine), direct path
start_daemons userspace
B4=$(overlay_ip $B "$WORK/b.sock")
wait_ping $A "$B4" || { echo "userspace overlay never came up"; exit 1; }
sleep 2 # let the path settle on direct
measure userspace $A $B "$B4"

# 2. relay: block WG's UDP between the nodes -> traffic falls to TCP relay
ns $A iptables -I OUTPUT 1 -p udp --dport 41642 -j DROP
ns $A iptables -I INPUT 1 -p udp --sport 41642 -j DROP
sleep 8 # WG re-handshakes over the relay path
if wait_ping $A "$B4"; then
  measure relay $A $B "$B4"
else
  echo "  relay      (path never recovered; skipped)"
fi
ns $A iptables -D OUTPUT -p udp --dport 41642 -j DROP
ns $A iptables -D INPUT -p udp --sport 41642 -j DROP
stop_daemons

# 3. kernel WireGuard (if the module is available)
if ns $A ip link add om-bn-probe type wireguard 2>/dev/null; then
  ns $A ip link del om-bn-probe
  start_daemons kernel
  B4=$(overlay_ip $B "$WORK/b.sock")
  if wait_ping $A "$B4"; then
    measure kernel $A $B "$B4"
  else
    echo "  kernel     (overlay never came up; skipped)"
  fi
  stop_daemons
else
  echo "  kernel     (wireguard module unavailable; skipped)"
fi

echo
log "done"
