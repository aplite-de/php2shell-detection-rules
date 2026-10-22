#!/usr/bin/env bash
# Thin wrapper around docker compose for the php2shell lab.
# Keeps everything on the isolated internal network; nothing is published.
set -euo pipefail
cd "$(dirname "$0")"

# Prefer the compose v2 plugin; fall back to the standalone docker-compose binary.
if docker compose version >/dev/null 2>&1; then
  compose() { docker compose "$@"; }
else
  compose() { docker-compose "$@"; }
fi

case "${1:-help}" in
  up)       compose up -d --build apache-vuln apache-fixed fpm-vuln fpm-fixed nginx-vuln nginx-fixed ;;
  down)     compose down -v ;;
  build)    compose build ;;
  ps)       compose ps ;;
  # Run the traffic generator; extra args pass through to lab.py
  traffic)  shift; compose run --rm --build traffic "$@" ;;
  # Reset logs between runs. Truncate files in place; do NOT remove the mounted
  # directories, or the bind mounts detach from the running containers.
  clean)    find logs -type f -name '*.log' -o -type f -name '*.json' -o -type f -name '*.jsonl' 2>/dev/null \
              | while read -r f; do : > "$f"; done
            echo "logs truncated" ;;
  logs)     shift; compose logs "$@" ;;
  *)        echo "usage: $0 {up|down|build|ps|traffic [args]|clean|logs [svc]}" ;;
esac
