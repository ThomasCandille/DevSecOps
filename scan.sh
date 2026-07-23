#!/usr/bin/env bash

set -Eeuo pipefail

VERSION="0.3.0"
TOTAL_STEPS=8

usage() {
  cat <<'TXT'
Usage :
  ./scan.sh http://127.0.0.1:3000
  ./scan.sh http://127.0.0.1:3000 --active

Modes :
  --passive  Reconnaissance et analyse sans mutation de paramètres (défaut).
  --active   Ajoute des tests limités sur les paramètres GET découverts.

Cette version accepte uniquement localhost, 127.0.0.1 ou ::1.
TXT
}

log_step() {
  local number="$1"
  shift
  printf '\n[%s/%s] %s\n' "$number" "$TOTAL_STEPS" "$*"
}

log_info() {
  printf '      -> %s\n' "$*"
}

log_ok() {
  printf '      [OK] %s\n' "$*"
}

log_warn() {
  printf '      [!] %s\n' "$*"
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 1
fi

TARGET="${1%/}"
MODE="passive"

if [[ $# -eq 2 ]]; then
  case "$2" in
    --active) MODE="active" ;;
    --passive) MODE="passive" ;;
    *)
      usage
      exit 1
      ;;
  esac
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_step 1 "Validation de la cible et du mode"

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
    echo "Erreur : cette version limite les scans aux cibles locales."
    exit 1
    ;;
esac

TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
OUTPUT_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

STATUS_FILE="$OUTPUT_DIR/tool-status.tsv"
printf 'tool\tstatus\n' > "$STATUS_FILE"

log_ok "Cible autorisee : $TARGET"
log_info "Hote : $HOST"
log_info "Port : $PORT"
log_info "Mode : $MODE"
log_info "Resultats : $OUTPUT_DIR"

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

  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\t%s\n' "$name" "missing" >> "$STATUS_FILE"
    log_warn "$name non installe : test ignore."
    return 0
  fi

  log_info "Lancement de $name"
  if "$@"; then
    printf '%s\t%s\n' "$name" "success" >> "$STATUS_FILE"
    log_ok "$name termine."
  else
    printf '%s\t%s\n' "$name" "failed" >> "$STATUS_FILE"
    log_warn "$name a retourne une erreur. Le reste du scan continue."
  fi
}

log_step 2 "Identification des technologies"
run_tool "whatweb" whatweb -a 1 "$TARGET" \
  --log-verbose="$OUTPUT_DIR/whatweb.txt"

log_step 3 "Analyse du port et du service"
run_tool "nmap" nmap -Pn -sV -p "$PORT" "$HOST" \
  -oN "$OUTPUT_DIR/nmap.txt"

log_step 4 "Decouverte de ressources"
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
  EXCLUDED_LENGTH="$(curl -ksS --max-time 10 "$TARGET/$RANDOM_PATH" | wc -c | tr -d ' ')"
  log_info "Taille d'une reponse inexistante : $EXCLUDED_LENGTH octets"

  run_tool "gobuster" gobuster dir \
    -u "$TARGET" \
    -w "$WORDLIST" \
    --exclude-length "$EXCLUDED_LENGTH" \
    -t 5 \
    -q \
    -o "$OUTPUT_DIR/gobuster.txt"
else
  printf '%s\t%s\n' "gobuster" "missing" >> "$STATUS_FILE"
  log_warn "Gobuster ou sa wordlist est introuvable : test ignore."
fi

log_step 5 "Recherche de mauvaises configurations"
if command -v nikto >/dev/null 2>&1; then
  log_info "Lancement de Nikto"
  if nikto \
    -h "$TARGET" \
    -nocheck \
    -nointeractive \
    -maxtime 5m \
    -Format txt \
    -output "$OUTPUT_DIR/nikto.txt" \
    > "$OUTPUT_DIR/nikto-console.txt" 2>&1; then
    printf '%s\t%s\n' "nikto" "success" >> "$STATUS_FILE"
    log_ok "Nikto termine."
  else
    printf '%s\t%s\n' "nikto" "failed" >> "$STATUS_FILE"
    log_warn "Nikto a retourne une erreur. Consulte nikto-console.txt."
  fi
else
  printf '%s\t%s\n' "nikto" "missing" >> "$STATUS_FILE"
  log_warn "Nikto non installe : test ignore."
fi

log_step 6 "Collecte HTTP"
log_info "Recuperation de la page, des headers et des cookies"
if curl -ksS \
  --max-time 15 \
  -D "$OUTPUT_DIR/headers.txt" \
  -c "$OUTPUT_DIR/cookies.txt" \
  -o "$OUTPUT_DIR/index.html" \
  "$TARGET"; then
  printf '%s\t%s\n' "curl" "success" >> "$STATUS_FILE"
  log_ok "Page principale recuperee."
else
  printf '%s\t%s\n' "curl" "failed" >> "$STATUS_FILE"
  log_warn "Impossible de recuperer la page principale."
fi

log_info "Verification des methodes HTTP annoncees"
curl -ksS --max-time 15 -X OPTIONS \
  -D "$OUTPUT_DIR/options-headers.txt" \
  -o "$OUTPUT_DIR/options-body.txt" \
  "$TARGET" || true

log_info "Verification de la politique CORS avec une origine externe fictive"
curl -ksS --max-time 15 \
  -H 'Origin: https://scanner.invalid' \
  -D "$OUTPUT_DIR/cors-headers.txt" \
  -o "$OUTPUT_DIR/cors-body.txt" \
  "$TARGET" || true

log_step 7 "Decouverte des routes et parametres"
log_info "Analyse du HTML et du JavaScript"
log_info "Les formulaires POST sont inventories mais ne sont pas testes automatiquement"

log_step 8 "Analyse, tests actifs et generation des rapports"
if [[ "$MODE" == "active" ]]; then
  log_warn "Mode actif : mutations limitees sur les parametres GET decouverts."
else
  log_info "Mode passif : aucun parametre ne sera modifie."
fi

python3 "$SCRIPT_DIR/scripts/analyse.py" \
  --target "$TARGET" \
  --input "$OUTPUT_DIR" \
  --mode "$MODE"

printf '\n============================================================\n'
printf ' Scan termine avec Web Security Scanner MVP %s\n' "$VERSION"
printf ' Mode         : %s\n' "$MODE"
printf ' Rapport HTML : %s/report.html\n' "$OUTPUT_DIR"
printf ' Rapport MD   : %s/report.md\n' "$OUTPUT_DIR"
printf ' Parametres   : %s/parameters.json\n' "$OUTPUT_DIR"
printf ' Tests actifs : %s/active-tests.json\n' "$OUTPUT_DIR"
printf '============================================================\n'
