#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="1.1.0"
TOTAL_STEPS=13
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
START_EPOCH="$(date +%s)"
NO_COLOR="${NO_COLOR:-}"
OPEN_REPORT="false"

if [[ -t 1 && -z "$NO_COLOR" ]]; then
  C_RESET=$'\033[0m'; C_BLUE=$'\033[1;34m'; C_GREEN=$'\033[1;32m'
  C_YELLOW=$'\033[1;33m'; C_RED=$'\033[1;31m'; C_DIM=$'\033[2m'
else
  C_RESET=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""
fi

timestamp() { date +'%H:%M:%S'; }
log_step() { printf '\n%s[%s] [%s/%s] %s%s\n' "$C_BLUE" "$(timestamp)" "$1" "$TOTAL_STEPS" "$2" "$C_RESET"; }
log_info() { printf '%s[%s] [INFO] %s%s\n' "$C_DIM" "$(timestamp)" "$*" "$C_RESET"; }
log_ok() { printf '%s[%s] [OK] %s%s\n' "$C_GREEN" "$(timestamp)" "$*" "$C_RESET"; }
log_warn() { printf '%s[%s] [WARN] %s%s\n' "$C_YELLOW" "$(timestamp)" "$*" "$C_RESET"; }
log_error() { printf '%s[%s] [ERROR] %s%s\n' "$C_RED" "$(timestamp)" "$*" "$C_RESET" >&2; }

usage() {
  cat <<'TXT'
DevSecOps Scanner V1.1

Usage :
  ./scan.sh URL [options]
  ./scan.sh --check

Exemples :
  ./scan.sh http://127.0.0.1:3000
  ./scan.sh http://127.0.0.1:3000 --active --har navigation.har
  ./scan.sh http://127.0.0.1:3000 --active --har navigation.har \
    --har-user-a user-a.har --har-user-b user-b.har --all-auth-tests

Options generales :
  --passive                    Cartographie sans mutation (defaut).
  --active                     Mutations limitees des entrees decouvertes.
  --active-post                Autorise certains POST/PUT/PATCH non sensibles du HAR.
  --har FICHIER                HAR principal exporte du navigateur ou de Burp.
  --use-har-auth               Rejoue Cookie/Authorization du HAR principal.
  --profile NOM                Profil applicatif : auto, none ou fichier de config/profiles.
  --max-active-targets N       Parametres testes : 15 par defaut, 50 maximum.
  --delay SECONDES             Pause entre requetes : 0.20 par defaut.
  --open-report                Ouvre le rapport HTML a la fin si possible.
  --no-color                   Desactive les couleurs du terminal.
  --check                      Verifie le projet et les outils puis quitte.

Authentification et autorisation :
  --har-user-a FICHIER         HAR d'un premier compte de laboratoire.
  --har-user-b FICHIER         HAR d'un second compte de laboratoire.
  --auth-config FICHIER        Configuration enumeration / limitation.
  --scenario-config FICHIER    Scenarios de logique metier.
  --auth-tests                 Enumeration limitee et anti-automation.
  --session-tests              Verifie l'invalidation apres logout.
  --access-tests               Compare les comptes A et B.
  --business-tests             Execute les scenarios explicitement actives.
  --all-auth-tests             Active les quatre familles precedentes.
  --max-access-tests N         Ressources comparees : 10 par defaut, 25 maximum.

OWASP ZAP :
  --zap                        Analyse ZAP passive.
  --zap-active                 Analyse ZAP active sur la cible fournie.

Les HAR et fichiers *.local.json peuvent contenir des secrets. Ne pas les publier.
TXT
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
  --check)
    exec python3 "$SCRIPT_DIR/scripts/self_check.py" --project "$SCRIPT_DIR"
    ;;
esac

[[ $# -ge 1 ]] || { usage; exit 1; }
TARGET="${1%/}"
shift

MODE="passive"
PROFILE="auto"
HAR_FILE=""
HAR_USER_A=""
HAR_USER_B=""
AUTH_CONFIG=""
SCENARIO_CONFIG=""
ACTIVE_POST="false"
USE_HAR_AUTH="false"
RUN_AUTH_TESTS="false"
RUN_SESSION_TESTS="false"
RUN_ACCESS_TESTS="false"
RUN_BUSINESS_TESTS="false"
ZAP_MODE="off"
MAX_ACTIVE_TARGETS="15"
MAX_ACCESS_TESTS="10"
DELAY="0.20"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --active) MODE="active"; shift ;;
    --passive) MODE="passive"; shift ;;
    --active-post) ACTIVE_POST="true"; MODE="active"; shift ;;
    --use-har-auth) USE_HAR_AUTH="true"; shift ;;
    --har) HAR_FILE="${2:?Fichier HAR manquant}"; shift 2 ;;
    --har=*) HAR_FILE="${1#*=}"; shift ;;
    --har-user-a) HAR_USER_A="${2:?HAR utilisateur A manquant}"; shift 2 ;;
    --har-user-a=*) HAR_USER_A="${1#*=}"; shift ;;
    --har-user-b) HAR_USER_B="${2:?HAR utilisateur B manquant}"; shift 2 ;;
    --har-user-b=*) HAR_USER_B="${1#*=}"; shift ;;
    --auth-config) AUTH_CONFIG="${2:?Configuration auth manquante}"; shift 2 ;;
    --auth-config=*) AUTH_CONFIG="${1#*=}"; shift ;;
    --scenario-config) SCENARIO_CONFIG="${2:?Configuration scenario manquante}"; shift 2 ;;
    --scenario-config=*) SCENARIO_CONFIG="${1#*=}"; shift ;;
    --auth-tests) RUN_AUTH_TESTS="true"; MODE="active"; shift ;;
    --session-tests) RUN_SESSION_TESTS="true"; MODE="active"; shift ;;
    --access-tests) RUN_ACCESS_TESTS="true"; MODE="active"; shift ;;
    --business-tests) RUN_BUSINESS_TESTS="true"; MODE="active"; shift ;;
    --all-auth-tests)
      RUN_AUTH_TESTS="true"; RUN_SESSION_TESTS="true"; RUN_ACCESS_TESTS="true"
      RUN_BUSINESS_TESTS="true"; MODE="active"; shift ;;
    --zap) ZAP_MODE="passive"; shift ;;
    --zap-active) ZAP_MODE="active"; MODE="active"; shift ;;
    --profile) PROFILE="${2:?Profil manquant}"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --max-active-targets) MAX_ACTIVE_TARGETS="${2:?Valeur manquante}"; shift 2 ;;
    --max-active-targets=*) MAX_ACTIVE_TARGETS="${1#*=}"; shift ;;
    --max-access-tests) MAX_ACCESS_TESTS="${2:?Valeur manquante}"; shift 2 ;;
    --max-access-tests=*) MAX_ACCESS_TESTS="${1#*=}"; shift ;;
    --delay) DELAY="${2:?Valeur manquante}"; shift 2 ;;
    --delay=*) DELAY="${1#*=}"; shift ;;
    --open-report) OPEN_REPORT="true"; shift ;;
    --no-color) NO_COLOR="1"; C_RESET=""; C_BLUE=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_DIM=""; shift ;;
    -h|--help) usage; exit 0 ;;
    *) log_error "Option inconnue : $1"; usage; exit 1 ;;
  esac
done

resolve_file() {
  local value="$1"
  [[ -z "$value" ]] && return 0
  python3 - "$value" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1]).expanduser().resolve()
if not path.is_file():
    raise SystemExit(f"Fichier introuvable : {path}")
print(path)
PY
}

update_meta() {
  local status="$1"
  local message="${2:-}"
  [[ -n "${META_DIR:-}" && -f "$META_DIR/scan.json" ]] || return 0
  python3 - "$META_DIR/scan.json" "$status" "$message" "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$START_EPOCH" <<'PY'
import json, sys, time
from pathlib import Path
path, status, message, completed, started_epoch = sys.argv[1:]
data = json.loads(Path(path).read_text(encoding="utf-8"))
data["status"] = status
data["message"] = message
data["updated_at_utc"] = completed
data["duration_seconds"] = max(0, int(time.time()) - int(started_epoch))
Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
PY
}

on_error() {
  local code=$?
  local line="${1:-?}"
  local command="${2:-?}"
  set +e
  log_error "Echec a la ligne $line : $command (code $code)"
  update_meta "failed" "Echec ligne $line, code $code"
  [[ -n "${LOG_DIR:-}" ]] && log_error "Journal : $LOG_DIR/console.log"
  exit "$code"
}
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

log_step 1 "Validation de la cible et des options"
command -v python3 >/dev/null 2>&1 || { log_error "python3 est requis."; exit 1; }
command -v curl >/dev/null 2>&1 || { log_error "curl est requis."; exit 1; }

readarray -t TARGET_INFO < <(
  python3 - "$TARGET" <<'PY'
import sys
from urllib.parse import urlsplit
parsed = urlsplit(sys.argv[1])
if parsed.scheme not in {"http", "https"} or not parsed.hostname:
    raise SystemExit("URL invalide. Exemple : http://127.0.0.1:3000")
print(parsed.hostname)
print(parsed.port or (443 if parsed.scheme == "https" else 80))
PY
)
HOST="${TARGET_INFO[0]}"
PORT="${TARGET_INFO[1]}"

log_ok "Cible validee : $TARGET"
log_warn "Utilisez ce scanner uniquement sur un site pour lequel vous disposez d une autorisation."

HAR_FILE="$(resolve_file "$HAR_FILE")"
HAR_USER_A="$(resolve_file "$HAR_USER_A")"
HAR_USER_B="$(resolve_file "$HAR_USER_B")"
AUTH_CONFIG="$(resolve_file "$AUTH_CONFIG")"
SCENARIO_CONFIG="$(resolve_file "$SCENARIO_CONFIG")"

[[ "$MAX_ACTIVE_TARGETS" =~ ^[0-9]+$ ]] && (( MAX_ACTIVE_TARGETS >= 1 && MAX_ACTIVE_TARGETS <= 50 )) || { log_error "--max-active-targets doit etre compris entre 1 et 50."; exit 1; }
[[ "$MAX_ACCESS_TESTS" =~ ^[0-9]+$ ]] && (( MAX_ACCESS_TESTS >= 1 && MAX_ACCESS_TESTS <= 25 )) || { log_error "--max-access-tests doit etre compris entre 1 et 25."; exit 1; }
python3 - "$DELAY" <<'PY'
import sys
value = float(sys.argv[1])
if not 0 <= value <= 10:
    raise SystemExit("--delay doit etre compris entre 0 et 10 secondes")
PY

UTC_STAMP="$(date -u +'%Y%m%dT%H%M%SZ')"
SCAN_ID="$(python3 - <<'PY'
import secrets
print(secrets.token_hex(4))
PY
)"
SAFE_HOST="$(printf '%s' "$HOST" | tr ':.' '--' | tr -cd 'A-Za-z0-9_-')"
TARGET_KEY="${SAFE_HOST}_${PORT}"
SCAN_NAME="${UTC_STAMP}_${MODE}_${SCAN_ID}"
SCAN_ROOT="$SCRIPT_DIR/results/$TARGET_KEY/$SCAN_NAME"
META_DIR="$SCAN_ROOT/00-meta"
RAW_TOOLS_DIR="$SCAN_ROOT/01-raw/tools"
RAW_HTTP_DIR="$SCAN_ROOT/01-raw/http"
STATIC_DIR="$SCAN_ROOT/02-static"
DYNAMIC_DIR="$SCAN_ROOT/03-dynamic"
AUTH_DIR="$SCAN_ROOT/04-authentication"
ACCESS_DIR="$SCAN_ROOT/05-access-control"
LOGIC_DIR="$SCAN_ROOT/06-business-logic"
ZAP_DIR="$SCAN_ROOT/07-zap"
REPORT_DIR="$SCAN_ROOT/08-report"
LOG_DIR="$SCAN_ROOT/09-logs"
mkdir -p "$META_DIR" "$RAW_TOOLS_DIR" "$RAW_HTTP_DIR" "$STATIC_DIR" "$REPORT_DIR" "$LOG_DIR"
exec > >(tee -a "$LOG_DIR/console.log") 2>&1

STATUS_FILE="$META_DIR/tool-status.tsv"
printf 'component\tstatus\tduration_seconds\tdetails\n' > "$STATUS_FILE"
python3 - "$META_DIR/scan.json" <<PY
import json
from pathlib import Path
payload = {
  "version": "$VERSION", "scan_id": "$SCAN_ID", "status": "running",
  "target": "$TARGET", "host": "$HOST", "port": int("$PORT"),
  "mode": "$MODE", "profile": "$PROFILE", "zap_mode": "$ZAP_MODE",
  "started_at_utc": "$(date -u +'%Y-%m-%dT%H:%M:%SZ')",
  "inputs": {"har": bool("$HAR_FILE"), "har_user_a": bool("$HAR_USER_A"), "har_user_b": bool("$HAR_USER_B"), "auth_config": bool("$AUTH_CONFIG"), "scenario_config": bool("$SCENARIO_CONFIG")},
  "enabled_tests": {"dynamic": "$MODE" == "active", "active_post": "$ACTIVE_POST" == "true", "authentication": "$RUN_AUTH_TESTS" == "true", "session": "$RUN_SESSION_TESTS" == "true", "access_control": "$RUN_ACCESS_TESTS" == "true", "business_logic": "$RUN_BUSINESS_TESTS" == "true"}
}
Path("$META_DIR/scan.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
PY
log_info "Scan ID : $SCAN_ID | mode : $MODE | profil : $PROFILE | ZAP : $ZAP_MODE"
log_info "Dossier : $SCAN_ROOT"

log_step 2 "Auto-diagnostic du projet et de l'environnement"
if python3 "$SCRIPT_DIR/scripts/self_check.py" --project "$SCRIPT_DIR" --json > "$META_DIR/environment.json"; then
  log_ok "Integrite du projet validee."
else
  log_error "L'auto-diagnostic a detecte une erreur bloquante."
  exit 1
fi
for optional in whatweb nmap gobuster nikto zaproxy; do
  command -v "$optional" >/dev/null 2>&1 || log_warn "$optional absent : le module correspondant sera ignore."
done

run_tool() {
  local name="$1"; shift
  local binary="$1"
  local started elapsed
  if ! command -v "$binary" >/dev/null 2>&1; then
    printf '%s\tmissing\t0\tcommande absente\n' "$name" >> "$STATUS_FILE"
    log_warn "$name non installe : test ignore."
    return 0
  fi
  started="$(date +%s)"
  log_info "Lancement de $name"
  if "$@"; then
    elapsed=$(( $(date +%s) - started ))
    printf '%s\tsuccess\t%s\tok\n' "$name" "$elapsed" >> "$STATUS_FILE"
    log_ok "$name termine en ${elapsed}s."
  else
    local code=$?
    elapsed=$(( $(date +%s) - started ))
    printf '%s\tfailed\t%s\tcode %s\n' "$name" "$elapsed" "$code" >> "$STATUS_FILE"
    log_warn "$name a retourne le code $code. Le scan continue."
  fi
}

log_step 3 "Identification des technologies"
run_tool "whatweb" whatweb -a 1 "$TARGET" --log-verbose="$RAW_TOOLS_DIR/whatweb.txt"

log_step 4 "Analyse du port et du service"
run_tool "nmap" nmap -Pn -sV -p "$PORT" "$HOST" -oN "$RAW_TOOLS_DIR/nmap.txt"

log_step 5 "Decouverte de ressources par dictionnaire"
WORDLIST=""
for candidate in /usr/share/wordlists/dirb/common.txt /usr/share/dirb/wordlists/common.txt; do
  [[ -f "$candidate" ]] && { WORDLIST="$candidate"; break; }
done
if [[ -n "$WORDLIST" ]] && command -v gobuster >/dev/null 2>&1; then
  RANDOM_PATH="route-inexistante-$RANDOM-$RANDOM"
  EXCLUDED_LENGTH="$(curl -ksS --max-time 10 "$TARGET/$RANDOM_PATH" 2>/dev/null | wc -c | tr -d ' ' || true)"
  EXCLUDED_LENGTH="${EXCLUDED_LENGTH:-0}"
  run_tool "gobuster" gobuster dir -u "$TARGET" -w "$WORDLIST" --exclude-length "$EXCLUDED_LENGTH" -t 5 -q -o "$RAW_TOOLS_DIR/gobuster.txt"
else
  printf 'gobuster\tmissing\t0\toutil ou wordlist absent\n' >> "$STATUS_FILE"
  log_warn "Gobuster ou sa wordlist est introuvable."
fi

log_step 6 "Recherche de mauvaises configurations"
if command -v nikto >/dev/null 2>&1; then
  started="$(date +%s)"
  if nikto -h "$TARGET" -nocheck -nointeractive -maxtime 5m -Format txt -output "$RAW_TOOLS_DIR/nikto.txt" > "$LOG_DIR/nikto-console.log" 2>&1; then
    elapsed=$(( $(date +%s) - started )); printf 'nikto\tsuccess\t%s\tok\n' "$elapsed" >> "$STATUS_FILE"; log_ok "Nikto termine en ${elapsed}s."
  else
    code=$?; elapsed=$(( $(date +%s) - started )); printf 'nikto\tfailed\t%s\tcode %s\n' "$elapsed" "$code" >> "$STATUS_FILE"; log_warn "Nikto a retourne le code $code."
  fi
else
  printf 'nikto\tmissing\t0\tcommande absente\n' >> "$STATUS_FILE"
  log_warn "Nikto absent."
fi

log_step 7 "Collecte HTTP initiale"
if curl -ksS --max-time 15 -D "$RAW_HTTP_DIR/headers.txt" -c "$RAW_HTTP_DIR/cookies.txt" -o "$RAW_HTTP_DIR/index.html" "$TARGET"; then
  printf 'curl\tsuccess\t0\tpage principale collectee\n' >> "$STATUS_FILE"
  log_ok "Page principale, headers et cookies recuperes."
else
  printf 'curl\tfailed\t0\trequete initiale echouee\n' >> "$STATUS_FILE"
  log_warn "La collecte HTTP initiale a echoue."
fi
curl -ksS --max-time 15 -X OPTIONS -D "$RAW_HTTP_DIR/options-headers.txt" -o "$RAW_HTTP_DIR/options-body.txt" "$TARGET" || true
curl -ksS --max-time 15 -H 'Origin: https://scanner.invalid' -D "$RAW_HTTP_DIR/cors-headers.txt" -o "$RAW_HTTP_DIR/cors-body.txt" "$TARGET" || true

log_step 8 "Cartographie et analyse statiques"
for file in whatweb.txt nmap.txt gobuster.txt nikto.txt; do [[ -e "$RAW_TOOLS_DIR/$file" ]] && ln -sfn "$RAW_TOOLS_DIR/$file" "$STATIC_DIR/$file"; done
for file in headers.txt cookies.txt index.html options-headers.txt options-body.txt cors-headers.txt cors-body.txt; do [[ -e "$RAW_HTTP_DIR/$file" ]] && ln -sfn "$RAW_HTTP_DIR/$file" "$STATIC_DIR/$file"; done
ln -sfn "$STATUS_FILE" "$STATIC_DIR/tool-status.tsv"
python3 "$SCRIPT_DIR/scripts/analyse.py" --target "$TARGET" --input "$STATIC_DIR" --mode "$MODE" --profile "$PROFILE" | tee "$LOG_DIR/static-analysis.log"
python3 "$SCRIPT_DIR/scripts/static_cleanup.py" --input "$STATIC_DIR" | tee "$LOG_DIR/static-cleanup.log"
log_ok "Cartographie statique terminee."

log_step 9 "Import HAR, parametres et mutations dynamiques"
if [[ -n "$HAR_FILE" ]]; then
  mkdir -p "$DYNAMIC_DIR"
  HAR_ARGS=(--target "$TARGET" --input "$DYNAMIC_DIR" --mode "$MODE" --max-active-targets "$MAX_ACTIVE_TARGETS" --delay "$DELAY" --har "$HAR_FILE")
  [[ "$ACTIVE_POST" == "true" ]] && HAR_ARGS+=(--active-post)
  [[ "$USE_HAR_AUTH" == "true" ]] && HAR_ARGS+=(--use-har-auth)
  python3 "$SCRIPT_DIR/scripts/har_active.py" "${HAR_ARGS[@]}" | tee "$LOG_DIR/dynamic-analysis.log"
else
  log_info "Aucun HAR fourni : module dynamique ignore."
fi

log_step 10 "Authentification, session, controle d'acces et logique metier"
if [[ "$RUN_AUTH_TESTS" == "true" || "$RUN_SESSION_TESTS" == "true" || "$RUN_ACCESS_TESTS" == "true" || "$RUN_BUSINESS_TESTS" == "true" ]]; then
  mkdir -p "$AUTH_DIR" "$ACCESS_DIR" "$LOGIC_DIR"
  AUTH_ARGS=(--target "$TARGET" --auth-output "$AUTH_DIR" --access-output "$ACCESS_DIR" --logic-output "$LOGIC_DIR" --max-access-tests "$MAX_ACCESS_TESTS" --delay "$DELAY")
  [[ -n "$HAR_USER_A" ]] && AUTH_ARGS+=(--har-user-a "$HAR_USER_A")
  [[ -n "$HAR_USER_B" ]] && AUTH_ARGS+=(--har-user-b "$HAR_USER_B")
  [[ -n "$AUTH_CONFIG" ]] && AUTH_ARGS+=(--auth-config "$AUTH_CONFIG")
  [[ -n "$SCENARIO_CONFIG" ]] && AUTH_ARGS+=(--scenario-config "$SCENARIO_CONFIG")
  [[ "$RUN_AUTH_TESTS" == "true" ]] && AUTH_ARGS+=(--auth-tests)
  [[ "$RUN_SESSION_TESTS" == "true" ]] && AUTH_ARGS+=(--session-tests)
  [[ "$RUN_ACCESS_TESTS" == "true" ]] && AUTH_ARGS+=(--access-tests)
  [[ "$RUN_BUSINESS_TESTS" == "true" ]] && AUTH_ARGS+=(--business-tests)
  python3 "$SCRIPT_DIR/scripts/auth_logic.py" "${AUTH_ARGS[@]}" | tee "$LOG_DIR/auth-access-business.log"
else
  log_info "Aucun test authentifie ou metier demande."
fi

log_step 11 "OWASP ZAP"
if [[ "$ZAP_MODE" != "off" ]]; then
  mkdir -p "$ZAP_DIR"
  started="$(date +%s)"
  if "$SCRIPT_DIR/scripts/zap_scan.sh" "$TARGET" "$ZAP_DIR" "$ZAP_MODE"; then
    elapsed=$(( $(date +%s) - started )); printf 'zap\tsuccess\t%s\tok\n' "$elapsed" >> "$STATUS_FILE"; log_ok "ZAP termine en ${elapsed}s."
  else
    code=$?; elapsed=$(( $(date +%s) - started )); printf 'zap\tfailed\t%s\tcode %s\n' "$elapsed" "$code" >> "$STATUS_FILE"; log_warn "ZAP indisponible ou en erreur."
  fi
else
  printf 'zap\tskipped\t0\tnon demande\n' >> "$STATUS_FILE"
  log_info "ZAP non demande."
fi

log_step 12 "Generation du rapport consolide"
update_meta "completed" "Analyses terminees, rapport en generation"
python3 "$SCRIPT_DIR/scripts/report.py" --scan-root "$SCAN_ROOT" --output "$REPORT_DIR" | tee "$LOG_DIR/report-generation.log"

log_step 13 "Validation finale et classement"
REPORT_HTML="$REPORT_DIR/security-assessment.html"
REPORT_JSON="$REPORT_DIR/security-assessment.json"
[[ -s "$REPORT_HTML" ]] || { log_error "Rapport HTML absent ou vide."; exit 1; }
python3 -m json.tool "$REPORT_JSON" >/dev/null
update_meta "completed" "Scan termine avec succes"
TARGET_RESULTS="$SCRIPT_DIR/results/$TARGET_KEY"
ln -sfn "$SCAN_ROOT" "$TARGET_RESULTS/latest"
ln -sfn "$REPORT_HTML" "$TARGET_RESULTS/latest-report.html"
DURATION=$(( $(date +%s) - START_EPOCH ))
log_ok "Rapports valides et scan classe."

printf '\n%s============================================================%s\n' "$C_GREEN" "$C_RESET"
printf ' DevSecOps Scanner V%s termine en %ss\n' "$VERSION" "$DURATION"
printf ' Scan ID : %s\n' "$SCAN_ID"
printf ' Dossier : %s\n' "$SCAN_ROOT"
printf ' Rapport : %s\n' "$REPORT_HTML"
printf ' Journal : %s/console.log\n' "$LOG_DIR"
printf '%s============================================================%s\n' "$C_GREEN" "$C_RESET"

if [[ "$OPEN_REPORT" == "true" ]]; then
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$REPORT_HTML" >/dev/null 2>&1 || log_warn "Impossible d'ouvrir automatiquement le rapport."
  else
    log_warn "xdg-open absent. Ouvrez manuellement le rapport."
  fi
fi
