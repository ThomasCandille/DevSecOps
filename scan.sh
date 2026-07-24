#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -eq 0 ]]; then
  echo "Usage: ./scan.sh URL [--active] [--har fichier.har] [--profile juice-shop]"
  exit 2
fi

exec python3 "$SCRIPT_DIR/scanner.py" "$@"
