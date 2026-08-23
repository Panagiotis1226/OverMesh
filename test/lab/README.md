# NAT-simulation lab

A reproducible network testbed for OverMesh development, built from Linux
network namespaces. Every later phase (holepunching, relay fallback,
exit-node benchmarks) runs its integration tests against this lab.

```
[client-a]---[nat-a]---+                +---[nat-b]---[client-b]
10.101.0.2  MASQUERADE |   [internet]   |  MASQUERADE  10.102.0.2
             192.0.2.10 +-- 192.0.2.1 --+  192.0.2.20
```

Both NAT gateways are stateful firewalls (only replies get back in) and
support two modes:

| Mode | iptables | Behavior |
|---|---|---|
| `cone` (default) | `MASQUERADE` | endpoint-independent mapping, port-restricted filtering — holepunchable |
| `symmetric` | `MASQUERADE --random-fully` | endpoint-dependent mapping — direct holepunching impossible, relay required |

## Usage (Linux, needs root)

```sh
sudo test/lab/lab.sh up                                   # cone <-> cone
sudo test/lab/lab.sh up --nat-a symmetric --nat-b cone    # mixed
sudo test/lab/lab.sh verify                               # run all checks
sudo test/lab/lab.sh exec client-a ping -c1 192.0.2.1     # poke around
sudo test/lab/lab.sh status
sudo test/lab/lab.sh down                                 # removes everything
```

`verify` asserts:

1. both clients reach the internet through their NAT,
2. unsolicited inbound traffic to the clients is dropped,
3. the clients cannot reach each other directly,
4. each NAT's observed mapping behavior (probed with
   `om-lab-udpecho`, a mini-STUN that sends from one socket to two
   destination ports and compares the mappings) matches its configured
   mode.

Everything lives in namespaces named `om-*`; `down` deletes them and
touches nothing else on the host.

## macOS / no root?

The lab needs Linux namespaces. On macOS run it inside any Linux VM
(lima/colima/OrbStack) or just rely on CI — the `lab-smoke` job runs
`up + verify + down` for both NAT modes on every push.
