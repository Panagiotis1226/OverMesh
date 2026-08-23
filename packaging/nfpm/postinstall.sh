#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  echo "overmesh installed. Start the daemon and join your mesh:"
  echo "  sudo systemctl enable --now overmeshd"
  echo "  sudo overmesh up -server <your-server>:41641 -key sk-..."
fi
