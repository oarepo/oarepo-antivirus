#!/usr/bin/env bash

set -euo pipefail

compose_file="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/tests/docker/docker-compose.yaml"

if [[ "$#" -eq 0 ]]; then
  docker compose -f "$compose_file" up -d --wait;
  exit 0;
elif [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 {start|stop}" >&2
  exit 1
fi

case "$1" in
  start)
    docker compose -f "$compose_file" up -d --wait
    ;;
  stop)
    docker compose -f "$compose_file" down
    ;;
  *)
    echo "Usage: $0 {start|stop}" >&2
    exit 1
    ;;
esac