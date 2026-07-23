#!/usr/bin/env bash

set -Eeuo pipefail

VERSION="0.5.0"
TOTAL_STEPS=9

usage() {
  cat <<'TXT'
Usage :
  ./scan.sh http://127.0.0.1:3000
  ./scan.sh http://127.0.0.1:3000 --active
  ./scan.sh http://127.0.0.1:3000 --active --profile juice-shop

Options :
  --passive          Cartographie et controles non destructifs (defaut).
  --active           Ajoute les mutations limitees sur les parametres GET.
  --profile NOM      Force un profil de routes (auto par defaut).
  --profile none     Desactive les profils applicatifs specifiques.

Cette version accepte uniquement localhost, 127.0.0.1 ou ::1.
TXT
}

log_step() { printf '\n[%s/%s] %s\n' "$1" "$TOTAL_STEPS" "$2"; }
log_info() { printf '      -> %s\n' "$*"; }
log_ok() { printf '      [OK] %s\n' "$*"; }
log_warn() { printf '      [!] %s\n' "$*"; }

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

TARGET="${1%/}"
shift
MODE="passive"
PROFILE="auto"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --active) MODE="active"; shift ;;
    --passive) MODE="passive"; shift ;;
    --profile)
      [[ $# -ge 2 ]] || { usage; exit 1; }
      PROFILE="$2"
      shift 2
      ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Option inconnue : $1"
      usage
      exit 1
      ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_step 1 "Validation de la cible et des options"
readarray -t TARGET_INFO < <(
  python3 - "$TARGET" <<'PY'
import sys
from urllib.parse import urlparse
url = sys.argv[1]
parsed = urlparse(url)
if parsed.scheme not in {"http", "https"} or not parsed.hostname:
    raise SystemExit("URL invalide. Exemple : http://127.0.0.1:3000")
print(parsed.hostname)
print(parsed.port or (443 if parsed.scheme == "https" else 80))
PY
)

HOST="${TARGET_INFO[0]}"
PORT="${TARGET_INFO[1]}"
case "$HOST" in
  localhost|127.0.0.1|::1) ;;
  *) echo "Erreur : cette version limite les scans aux cibles locales."; exit 1 ;;
esac

command -v python3 >/dev/null 2>&1 || { echo "Commande requise absente : python3"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "Commande requise absente : curl"; exit 1; }

TIMESTAMP="$(date +'%Y-%m-%d_%H-%M-%S')"
OUTPUT_DIR="$SCRIPT_DIR/results/$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"
STATUS_FILE="$OUTPUT_DIR/tool-status.tsv"
printf 'tool\tstatus\n' > "$STATUS_FILE"

log_ok "Cible autorisee : $TARGET"
log_info "Hote : $HOST"
log_info "Port : $PORT"
log_info "Mode : $MODE"
log_info "Profil : $PROFILE"
log_info "Resultats : $OUTPUT_DIR"

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
    log_warn "$name a retourne une erreur. Le scan continue."
  fi
}

log_step 2 "Identification des technologies"
run_tool "whatweb" whatweb -a 1 "$TARGET" --log-verbose="$OUTPUT_DIR/whatweb.txt"

log_step 3 "Analyse du port et du service"
run_tool "nmap" nmap -Pn -sV -p "$PORT" "$HOST" -oN "$OUTPUT_DIR/nmap.txt"

log_step 4 "Decouverte de ressources par dictionnaire"
WORDLIST=""
for candidate in /usr/share/wordlists/dirb/common.txt /usr/share/dirb/wordlists/common.txt; do
  [[ -f "$candidate" ]] && { WORDLIST="$candidate"; break; }
done

if [[ -n "$WORDLIST" ]] && command -v gobuster >/dev/null 2>&1; then
  RANDOM_PATH="route-inexistante-$RANDOM-$RANDOM"
  EXCLUDED_LENGTH="$(curl -ksS --max-time 10 "$TARGET/$RANDOM_PATH" | wc -c | tr -d ' ')"
  log_info "Taille de la page inexistante : $EXCLUDED_LENGTH octets"
  run_tool "gobuster" gobuster dir \
    -u "$TARGET" \
    -w "$WORDLIST" \
    --exclude-length "$EXCLUDED_LENGTH" \
    -t 5 \
    -q \
    -o "$OUTPUT_DIR/gobuster.txt"
else
  printf '%s\t%s\n' "gobuster" "missing" >> "$STATUS_FILE"
  log_warn "Gobuster ou sa wordlist est introuvable."
fi

log_step 5 "Recherche de mauvaises configurations"
if command -v nikto >/dev/null 2>&1; then
  log_info "Lancement de Nikto"
  if nikto -h "$TARGET" -nocheck -nointeractive -maxtime 5m -Format txt \
      -output "$OUTPUT_DIR/nikto.txt" > "$OUTPUT_DIR/nikto-console.txt" 2>&1; then
    printf '%s\t%s\n' "nikto" "success" >> "$STATUS_FILE"
    log_ok "Nikto termine."
  else
    printf '%s\t%s\n' "nikto" "failed" >> "$STATUS_FILE"
    log_warn "Nikto a retourne une erreur. Consulte nikto-console.txt."
  fi
else
  printf '%s\t%s\n' "nikto" "missing" >> "$STATUS_FILE"
  log_warn "Nikto non installe."
fi

log_step 6 "Collecte HTTP initiale"
log_info "Recuperation de la page, des headers et des cookies"
if curl -ksS --max-time 15 -D "$OUTPUT_DIR/headers.txt" -c "$OUTPUT_DIR/cookies.txt" \
    -o "$OUTPUT_DIR/index.html" "$TARGET"; then
  printf '%s\t%s\n' "curl" "success" >> "$STATUS_FILE"
  log_ok "Page principale recuperee."
else
  printf '%s\t%s\n' "curl" "failed" >> "$STATUS_FILE"
  log_warn "Impossible de recuperer la page principale."
fi

log_info "Verification des methodes HTTP"
curl -ksS --max-time 15 -X OPTIONS -D "$OUTPUT_DIR/options-headers.txt" \
  -o "$OUTPUT_DIR/options-body.txt" "$TARGET" || true

log_info "Verification CORS avec une origine externe fictive"
curl -ksS --max-time 15 -H 'Origin: https://scanner.invalid' \
  -D "$OUTPUT_DIR/cors-headers.txt" -o "$OUTPUT_DIR/cors-body.txt" "$TARGET" || true

log_step 7 "Cartographie des routes, scripts et parametres"
log_info "Exploration HTML limitee, analyse contextuelle du JavaScript et profils de routes sensibles"
log_info "Les routes SPA, les API, robots.txt, sitemap.xml et les resultats Gobuster seront fusionnes"

log_step 8 "Tests limites et generation des rapports"
if [[ "$MODE" == "active" ]]; then
  log_warn "Mode actif : mutations limitees aux parametres GET fiables."
else
  log_info "Mode passif : aucune mutation de parametre."
fi

python3 "$SCRIPT_DIR/scripts/analyse.py" \
  --target "$TARGET" \
  --input "$OUTPUT_DIR" \
  --mode "$MODE" \
  --profile "$PROFILE"

log_step 9 "Nettoyage et consolidation du rapport"

log_info "Filtrage des faux endpoints et deduplication des constats"

if python3 "$SCRIPT_DIR/scripts/report_clean.py" \
  --input "$OUTPUT_DIR"; then
    log_ok "Rapport consolide genere."
else
    log_warn "La generation du rapport consolide a echoue."
fi

printf '\n============================================================\n'
printf ' Scan termine avec Web Security Scanner MVP %s\n' "$VERSION"
printf ' Mode              : %s\n' "$MODE"
printf ' Profil            : %s\n' "$PROFILE"
printf ' Rapport principal : %s/report-clean.html\n' "$OUTPUT_DIR"
printf ' Rapport brut      : %s/report.html\n' "$OUTPUT_DIR"
printf ' Rapport Markdown  : %s/report-clean.md\n' "$OUTPUT_DIR"
printf ' Rapport JSON      : %s/report-clean.json\n' "$OUTPUT_DIR"
printf ' Routes sensibles  : %s/sensitive-routes.json\n' "$OUTPUT_DIR"
printf ' Endpoints         : %s/endpoints.json\n' "$OUTPUT_DIR"
printf ' Parametres        : %s/parameters.json\n' "$OUTPUT_DIR"
printf ' Tests actifs      : %s/active-tests.json\n' "$OUTPUT_DIR"
printf '============================================================\n'
