#!/usr/bin/env bash
# Update NSM-10 to the latest version from GitHub and restart it.
#
#   First time:   curl -fsSL https://raw.githubusercontent.com/insecurityfyi/nms-10/main/update.sh | sudo bash
#   After that:   sudo nsm-update
#
# Finds the folder the running app was started from, turns it into a git clone
# if it is not one yet (the old folder is kept as <folder>-old-<date>), pulls
# the latest code and rebuilds the container. Settings live in a Docker volume
# and are kept.
set -euo pipefail

main() {
  local repo="https://github.com/insecurityfyi/nms-10" dir
  if [ "$(id -u)" != 0 ]; then echo "Run with sudo: sudo nsm-update" >&2; exit 1; fi
  command -v git >/dev/null 2>&1 || { apt-get update && apt-get install -y git; }

  dir=$(docker inspect nsm10 --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null || true)
  if [ -z "$dir" ]; then
    dir="${NSM_DIR:-/opt/nsm-10}"
    echo "No running nsm10 container found; installing to $dir"
  fi
  echo "App folder: $dir"

  if [ ! -d "$dir/.git" ]; then
    if [ -e "$dir" ]; then
      local backup="$dir-old-$(date +%Y%m%d-%H%M%S)"
      echo "Not a git clone yet; keeping the current folder as $backup"
      mv "$dir" "$backup"
    fi
    git clone "$repo" "$dir"
  fi

  cd "$dir"
  local before after
  before=$(git rev-parse --short HEAD)
  git pull --ff-only
  after=$(git rev-parse --short HEAD)
  install -m 755 update.sh /usr/local/bin/nsm-update
  bash install.sh
  if [ "$before" = "$after" ]; then echo "Already up to date ($after); container rebuilt."; else echo "Updated $before -> $after."; fi
}

main "$@"
