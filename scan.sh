#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -eq 0 ]]; then
  cat <<'USAGE'
DevSecOps Scanner 2.1.0

Usage minimal :
  ./scan.sh URL
  ./scan.sh URL --active

Couverture dynamique :
  ./scan.sh URL --active --har navigation.har
  ./scan.sh URL --active --active-post --har navigation.har

Deux comptes et session :
  ./scan.sh URL --active \
    --har-user-a user-a.har --har-user-b user-b.har \
    --use-har-auth --access-tests --session-tests

API et navigateur :
  ./scan.sh URL --active --openapi openapi.json
  ./scan.sh URL --active --graphql-url /graphql --graphql-introspection
  ./scan.sh URL --active --no-zap-ajax

Modules optionnels :
  --sqlmap              confirmation SQLi ciblee
  --nuclei              templates Nuclei, desactives par defaut
  --no-zap              desactive ZAP, meme en mode actif

Aide complete :
  python3 scanner.py --help
USAGE
  exit 2
fi

exec python3 "$SCRIPT_DIR/scanner.py" "$@"
