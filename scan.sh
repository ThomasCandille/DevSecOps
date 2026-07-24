#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -eq 0 ]]; then
  cat <<'USAGE'
Usage:
  ./scan.sh URL [--active] [--har fichier.har] [--profile juice-shop]
  ./scan.sh URL --active --nuclei [--nuclei-timeout 120]

Nuclei est desactive par defaut pour ne pas bloquer les scans actifs.
USAGE
  exit 2
fi

exec python3 "$SCRIPT_DIR/scanner.py" "$@"
