#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  cat <<'TXT'
Usage:
  ./scan.sh http://127.0.0.1:3000

Ce MVP accepte uniquement localhost, 127.0.0.1 ou ::1.
TXT
}

if [[ $# -ne 1 ]]; then
  usage
  exit 1
fi

TARGET="${1%/}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

readarray -t TARGET_INFO < <(
  python3 - "$TARGET" <<'PY'
import sys
from urllib.parse import urlparse

url = sys.argv[1]
parsed = urlparse(url)

if parsed.scheme not in {"http", "https"} or not parsed.hostname:
    raise SystemExit("URL invalide. Exemple : http://127.0.0.1:3000")

port = parsed.port or (443 if parsed.scheme == "https" else 80)
print(parsed.hostname)
print(port)
PY
)

HOST="${TARGET_INFO[0]}"
PORT="${TARGET_INFO[1]}"

case "$HOST" in
  localhost|127.0.0.1|::1) ;;
  *)
    echo "Erreur : ce MVP limite les scans aux cibles locales."
    exit 1
    ;;
esac

TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
OUTPUT_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

STATUS_FILE="$OUTPUT_DIR/tool-status.tsv"
printf 'tool\tstatus\n' > "$STATUS_FILE"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Commande requise absente : $1"
    exit 1
  fi
}

require_command python3
require_command curl

run_tool() {
  local name="$1"
  shift

  echo "[$name] lancement"
  if command -v "$1" >/dev/null 2>&1; then
    if "$@"; then
      printf '%s\t%s\n' "$name" "success" >> "$STATUS_FILE"
    else
      printf '%s\t%s\n' "$name" "failed" >> "$STATUS_FILE"
      echo "[$name] termine avec une erreur. Consulte le fichier de sortie."
    fi
  else
    printf '%s\t%s\n' "$name" "missing" >> "$STATUS_FILE"
    echo "[$name] non installe, test ignore."
  fi
}

echo "Cible       : $TARGET"
echo "Hote        : $HOST"
echo "Port        : $PORT"
echo "Resultats   : $OUTPUT_DIR"
echo

run_tool "whatweb" whatweb -a 1 "$TARGET" \
  --log-verbose="$OUTPUT_DIR/whatweb.txt"

run_tool "nmap" nmap -Pn -sV -p "$PORT" "$HOST" \
  -oN "$OUTPUT_DIR/nmap.txt"

WORDLIST=""
for candidate in \
  /usr/share/wordlists/dirb/common.txt \
  /usr/share/dirb/wordlists/common.txt; do
  if [[ -f "$candidate" ]]; then
    WORDLIST="$candidate"
    break
  fi
done

if [[ -n "$WORDLIST" ]] && command -v gobuster >/dev/null 2>&1; then
  RANDOM_PATH="route-inexistante-$RANDOM-$RANDOM"
  EXCLUDED_LENGTH="$(curl -ksS "$TARGET/$RANDOM_PATH" | wc -c | tr -d ' ')"

  run_tool "gobuster" gobuster dir \
    -u "$TARGET" \
    -w "$WORDLIST" \
    --exclude-length "$EXCLUDED_LENGTH" \
    -t 5 \
    -q \
    -o "$OUTPUT_DIR/gobuster.txt"
else
  printf '%s\t%s\n' "gobuster" "missing" >> "$STATUS_FILE"
  echo "[gobuster] outil ou wordlist introuvable, test ignore."
fi

if command -v nikto >/dev/null 2>&1; then
  echo "[nikto] lancement"
  if nikto \
    -h "$TARGET" \
    -nocheck \
    -nointeractive \
    -maxtime 5m \
    -Format txt \
    -output "$OUTPUT_DIR/nikto.txt" \
    > "$OUTPUT_DIR/nikto-console.txt" 2>&1; then
    printf '%s\t%s\n' "nikto" "success" >> "$STATUS_FILE"
  else
    printf '%s\t%s\n' "nikto" "failed" >> "$STATUS_FILE"
    echo "[nikto] termine avec une erreur."
  fi
else
  printf '%s\t%s\n' "nikto" "missing" >> "$STATUS_FILE"
  echo "[nikto] non installe, test ignore."
fi

echo "[http] collecte des en-tetes et de la page"
if curl -ksS \
  --max-time 15 \
  -D "$OUTPUT_DIR/headers.txt" \
  -o "$OUTPUT_DIR/index.html" \
  "$TARGET"; then
  printf '%s\t%s\n' "curl" "success" >> "$STATUS_FILE"
else
  printf '%s\t%s\n' "curl" "failed" >> "$STATUS_FILE"
fi

python3 "$SCRIPT_DIR/scripts/analyse.py" \
  --target "$TARGET" \
  --input "$OUTPUT_DIR"

echo
echo "Analyse terminee."
echo "Rapport : $OUTPUT_DIR/report.md"
