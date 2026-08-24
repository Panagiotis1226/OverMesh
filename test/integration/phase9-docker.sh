#!/usr/bin/env bash
# Runs the Phase 9 mobilecore exit test (test/integration/phase9.sh)
# inside a privileged Linux container — the way to run it on macOS,
# where there is no /dev/net/tun or netns. Requires Docker.
#
#   test/integration/phase9-docker.sh
#
# The host Go module cache is mounted in so repeat runs need almost
# no network.
set -euo pipefail

cd "$(dirname "$0")/../.."   # repo root

GOMODCACHE_HOST=$(go env GOMODCACHE 2>/dev/null || echo "$HOME/go/pkg/mod")
GO_IMAGE=golang:1.27

exec docker run --rm --privileged \
  -v "$PWD":/src \
  -v "$GOMODCACHE_HOST":/gomod -e GOMODCACHE=/gomod -e GOFLAGS=-mod=mod \
  -w /src "$GO_IMAGE" bash -c '
    set -euo pipefail
    apt-get update -qq >/dev/null
    # NB: iputils-ping — the golang image lacks ping, and phase9.sh
    # would fail its connectivity checks without it.
    apt-get install -y -qq iproute2 iptables curl iputils-ping >/dev/null 2>&1
    go build -o bin/overmesh-server ./cmd/overmesh-server
    go build -o bin/overmeshd ./cmd/overmeshd
    go build -o bin/overmesh ./cmd/overmesh
    go build -o bin/om-mobileharness ./test/mobileharness
    test/integration/phase9.sh
  '
