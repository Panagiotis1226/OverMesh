#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop overmeshd 2>/dev/null || true
  systemctl disable overmeshd 2>/dev/null || true
fi
