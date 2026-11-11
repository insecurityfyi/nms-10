#!/usr/bin/env bash
# Run on the Ubuntu server, from the nsm-10 folder: sudo bash install.sh
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v docker >/dev/null 2>&1; then
  echo "Installing Docker..."
  apt-get update
  apt-get install -y docker.io docker-compose-v2
  systemctl enable --now docker
fi
docker compose up -d --build
echo
echo "NSM-10 is running: http://$(hostname -I | awk '{print $1}'):8080"
