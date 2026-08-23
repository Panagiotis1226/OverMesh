#!/usr/bin/env bash
# OverMesh NAT-simulation lab (Linux network namespaces).
#
# Topology:
#
#   [om-cl-a]---[om-nat-a]---+                +---[om-nat-b]---[om-cl-b]
#   10.101.0.2  MASQUERADE   |   [om-inet]    |   MASQUERADE   10.102.0.2
#                192.0.2.10  +--- 192.0.2.1 --+   192.0.2.20
#                                (bridge br0)
#
# Each NAT gateway can run in one of two modes:
#   cone       plain MASQUERADE: endpoint-independent mapping,
#              address-and-port-restricted filtering ("port-restricted cone")
#   symmetric  MASQUERADE --random-fully: endpoint-dependent mapping
#
# Usage:
#   sudo test/lab/lab.sh up [--nat-a cone|symmetric] [--nat-b cone|symmetric]
#   sudo test/lab/lab.sh verify
#   sudo test/lab/lab.sh status
#   sudo test/lab/lab.sh exec <inet|nat-a|nat-b|client-a|client-b> <cmd...>
#   sudo test/lab/lab.sh down
#
# Everything lives in namespaces named om-*; `down` removes them all and
# touches nothing else on the host.

set -euo pipefail

STATE_DIR=/run/overmesh-lab
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UDPECHO="$REPO_ROOT/bin/om-lab-udpecho"

INET=om-inet
NATA=om-nat-a
NATB=om-nat-b
CLA=om-cl-a
CLB=om-cl-b

# Addressing (TEST-NET-1 for the fake internet, RFC1918 for the LANs).
INET_IP=192.0.2.1
NATA_WAN=192.0.2.10
NATB_WAN=192.0.2.20
LANA_GW=10.101.0.1
LANA_CL=10.101.0.2
LANB_GW=10.102.0.1
LANB_CL=10.102.0.2

ECHO_PORT1=9998
ECHO_PORT2=9999

die() { echo "lab: $*" >&2; exit 1; }
need_root() { [ "$(id -u)" = 0 ] || die "must run as root (try sudo)"; }
ns() { ip netns exec "$@"; }

ns_name() {
  case "$1" in
    inet) echo "$INET" ;;
    nat-a) echo "$NATA" ;;
    nat-b) echo "$NATB" ;;
    client-a) echo "$CLA" ;;
    client-b) echo "$CLB" ;;
    *) die "unknown lab host '$1' (want inet|nat-a|nat-b|client-a|client-b)" ;;
  esac
}

up() {
  local mode_a=cone mode_b=cone
  while [ $# -gt 0 ]; do
    case "$1" in
      --nat-a) mode_a="$2"; shift 2 ;;
      --nat-b) mode_b="$2"; shift 2 ;;
      *) die "unknown flag $1" ;;
    esac
  done
  case "$mode_a" in cone|symmetric) ;; *) die "--nat-a must be cone|symmetric" ;; esac
  case "$mode_b" in cone|symmetric) ;; *) die "--nat-b must be cone|symmetric" ;; esac

  [ -e "$STATE_DIR/state" ] && die "lab already up (run 'down' first)"

  echo "lab: building topology (nat-a=$mode_a, nat-b=$mode_b)"
  for n in $INET $NATA $NATB $CLA $CLB; do ip netns add "$n"; done
  for n in $INET $NATA $NATB $CLA $CLB; do ns "$n" ip link set lo up; done

  # The internet: a bridge both NAT gateways plug into.
  ns "$INET" ip link add br0 type bridge
  ns "$INET" ip addr add "$INET_IP/24" dev br0
  ns "$INET" ip link set br0 up

  wire_side a "$NATA" "$CLA" "$NATA_WAN" "$LANA_GW" "$LANA_CL" 10.101.0.0/24
  wire_side b "$NATB" "$CLB" "$NATB_WAN" "$LANB_GW" "$LANB_CL" 10.102.0.0/24

  nat_rules "$NATA" "$mode_a" 10.101.0.0/24
  nat_rules "$NATB" "$mode_b" 10.102.0.0/24

  # Routes from the internet toward the private LANs, via each NAT's WAN
  # address. Without these, "inbound to a private address" would fail for
  # the boring reason (no route); with them the packet reaches the NAT and
  # is dropped by its stateful firewall — the behavior we actually want to
  # simulate.
  ns "$INET" ip route add 10.101.0.0/24 via "$NATA_WAN"
  ns "$INET" ip route add 10.102.0.0/24 via "$NATB_WAN"
  ns "$NATA" ip route add 10.102.0.0/24 via "$NATB_WAN"
  ns "$NATB" ip route add 10.101.0.0/24 via "$NATA_WAN"

  mkdir -p "$STATE_DIR"
  printf 'mode_a=%s\nmode_b=%s\n' "$mode_a" "$mode_b" > "$STATE_DIR/state"

  # UDP echo server on the "internet" (used by verify and by hand).
  build_udpecho
  ns "$INET" "$UDPECHO" -listen "$INET_IP:$ECHO_PORT1,$INET_IP:$ECHO_PORT2" \
    >"$STATE_DIR/udpecho.log" 2>&1 &
  echo $! > "$STATE_DIR/udpecho.pid"

  echo "lab: up. Try:  sudo $0 verify"
}

# wire_side <a|b> <natns> <clns> <wan_ip> <lan_gw> <lan_cl> <lan_cidr>
wire_side() {
  local side="$1" natns="$2" clns="$3" wan_ip="$4" lan_gw="$5" lan_cl="$6" lan_cidr="$7"

  # WAN veth: one end in the NAT ns, the other on the internet bridge.
  ip link add "w${side}0" type veth peer name "w${side}1"
  ip link set "w${side}0" netns "$natns"
  ip link set "w${side}1" netns "$INET"
  ns "$natns" ip addr add "$wan_ip/24" dev "w${side}0"
  ns "$natns" ip link set "w${side}0" up
  ns "$INET" ip link set "w${side}1" master br0
  ns "$INET" ip link set "w${side}1" up

  # LAN veth: NAT ns <-> client ns.
  ip link add "l${side}0" type veth peer name "l${side}1"
  ip link set "l${side}0" netns "$clns"
  ip link set "l${side}1" netns "$natns"
  ns "$natns" ip addr add "$lan_gw/24" dev "l${side}1"
  ns "$natns" ip link set "l${side}1" up
  ns "$clns" ip addr add "$lan_cl/24" dev "l${side}0"
  ns "$clns" ip link set "l${side}0" up
  ns "$clns" ip route add default via "$lan_gw"
  ns "$natns" ip route add default via "$INET_IP"
}

# nat_rules <natns> <cone|symmetric> <lan_cidr>
nat_rules() {
  local natns="$1" mode="$2" lan="$3"
  ns "$natns" sysctl -qw net.ipv4.ip_forward=1

  local extra=""
  [ "$mode" = symmetric ] && extra="--random-fully"
  # shellcheck disable=SC2086
  ns "$natns" iptables -t nat -A POSTROUTING -s "$lan" ! -d "$lan" -j MASQUERADE $extra

  # Stateful firewall: LAN may go out, only replies come back in.
  ns "$natns" iptables -A FORWARD -s "$lan" -j ACCEPT
  ns "$natns" iptables -A FORWARD -d "$lan" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ns "$natns" iptables -A FORWARD -d "$lan" -j DROP

  # Drop unsolicited traffic addressed to the router's WAN side, like any
  # real CPE. Critically, an ACCEPT-all INPUT would CONFIRM conntrack
  # entries for stray inbound UDP (e.g. a peer's holepunch checks arriving
  # a moment early), which then collides with the LAN host's own outbound
  # mapping and forces MASQUERADE onto a different port — breaking the
  # port-preserving simultaneous open that real-world holepunching
  # depends on.
  ns "$natns" iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ns "$natns" iptables -A INPUT -i "l${natns: -1}1" -j ACCEPT # LAN side stays open
  ns "$natns" iptables -A INPUT -i lo -j ACCEPT
  ns "$natns" iptables -A INPUT -j DROP
}

build_udpecho() {
  if [ ! -x "$UDPECHO" ]; then
    echo "lab: building om-lab-udpecho"
    (cd "$REPO_ROOT" && go build -o "$UDPECHO" ./test/lab/udpecho) \
      || die "go build failed — build bin/om-lab-udpecho on a machine with Go and copy it in"
  fi
}

down() {
  if [ -f "$STATE_DIR/udpecho.pid" ]; then
    kill "$(cat "$STATE_DIR/udpecho.pid")" 2>/dev/null || true
  fi
  for n in $INET $NATA $NATB $CLA $CLB; do
    ip netns del "$n" 2>/dev/null || true
  done
  rm -rf "$STATE_DIR"
  echo "lab: down"
}

status() {
  [ -f "$STATE_DIR/state" ] || { echo "lab: not up"; return 1; }
  cat "$STATE_DIR/state"
  ip netns list | grep '^om-' || true
}

# verify: the Phase 0 exit test.
verify() {
  [ -f "$STATE_DIR/state" ] || die "lab not up (run 'up' first)"
  # shellcheck disable=SC1091
  . "$STATE_DIR/state"
  build_udpecho
  local fails=0

  check() { # check <desc> <expect_rc0|expect_fail> <cmd...>
    local desc="$1" expect="$2"; shift 2
    local rc=0
    "$@" >/dev/null 2>&1 || rc=$?
    if { [ "$expect" = ok ] && [ $rc -eq 0 ]; } || { [ "$expect" = fail ] && [ $rc -ne 0 ]; }; then
      echo "  PASS  $desc"
    else
      echo "  FAIL  $desc (rc=$rc, expected $expect)"
      fails=$((fails+1))
    fi
  }

  echo "lab: verifying (nat-a=$mode_a, nat-b=$mode_b)"
  check "client-a reaches the internet through its NAT"  ok   ns "$CLA" ping -c1 -W2 "$INET_IP"
  check "client-b reaches the internet through its NAT"  ok   ns "$CLB" ping -c1 -W2 "$INET_IP"
  check "internet cannot reach client-a (unsolicited inbound dropped)" fail ns "$INET" ping -c1 -W1 "$LANA_CL"
  check "internet cannot reach client-b (unsolicited inbound dropped)" fail ns "$INET" ping -c1 -W1 "$LANB_CL"
  check "client-a cannot reach client-b directly (both behind NAT)"    fail ns "$CLA" ping -c1 -W1 "$LANB_CL"

  verify_mapping a "$CLA" "$mode_a" || fails=$((fails+1))
  verify_mapping b "$CLB" "$mode_b" || fails=$((fails+1))

  if [ $fails -gt 0 ]; then
    echo "lab: FAILED ($fails checks)"
    return 1
  fi
  echo "lab: all checks passed"
}

# verify_mapping <side> <clns> <mode>: probe both echo ports from one
# socket and assert the NAT's mapping behavior matches its configured mode.
verify_mapping() {
  local side="$1" clns="$2" mode="$3"
  local want out verdict
  case "$mode" in
    cone) want=endpoint-independent ;;
    symmetric) want=endpoint-dependent ;;
  esac
  out="$(ns "$clns" "$UDPECHO" -probe "$INET_IP:$ECHO_PORT1,$INET_IP:$ECHO_PORT2" 2>&1)" || {
    echo "  FAIL  NAT mapping probe from client-$side: $out"
    return 1
  }
  verdict="$(printf '%s\n' "$out" | sed -n 's/^verdict=//p')"
  if [ "$verdict" = "$want" ]; then
    echo "  PASS  client-$side NAT mapping is $verdict (mode=$mode)"
  else
    echo "  FAIL  client-$side NAT mapping: got $verdict, want $want (mode=$mode)"
    printf '%s\n' "$out" | sed 's/^/        /'
    return 1
  fi
}

main() {
  need_root
  command -v ip >/dev/null || die "iproute2 not installed"
  command -v iptables >/dev/null || die "iptables not installed"
  local cmd="${1:-}"
  shift || true
  case "$cmd" in
    up) up "$@" ;;
    down) down ;;
    status) status ;;
    verify) verify ;;
    exec) local n; n="$(ns_name "$1")"; shift; ns "$n" "$@" ;;
    *) die "usage: lab.sh up|down|status|verify|exec (see header comment)" ;;
  esac
}

main "$@"
