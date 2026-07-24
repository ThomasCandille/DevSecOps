#!/usr/bin/env bash
set -Eeuo pipefail

TARGET="${1:?Cible manquante}"
OUTPUT_DIR="${2:?Dossier de sortie manquant}"
MODE="${3:-passive}"
mkdir -p "$OUTPUT_DIR"

log() { printf ' -> %s\n' "$*"; }
ok() { printf ' [OK] %s\n' "$*"; }
warn() { printf ' [!] %s\n' "$*"; }

if [[ "$MODE" == "active" ]]; then
  SCAN_SCRIPT="zap-full-scan.py"
  EXTRA_ARGS=(-m 3 -I)
  log "ZAP actif explicitement demande : spider puis scan actif limite"
else
  SCAN_SCRIPT="zap-baseline.py"
  EXTRA_ARGS=(-m 2 -I)
  log "ZAP passif : spider puis analyse passive"
fi

if command -v "$SCAN_SCRIPT" >/dev/null 2>&1; then
  if "$SCAN_SCRIPT" -t "$TARGET" "${EXTRA_ARGS[@]}" \
      -J "$OUTPUT_DIR/zap-report.json" \
      -r "$OUTPUT_DIR/zap-report.html" \
      > "$OUTPUT_DIR/zap-console.log" 2>&1; then
    ok "Rapport ZAP genere."
    exit 0
  fi
  warn "$SCAN_SCRIPT a retourne une erreur."
fi

if command -v docker >/dev/null 2>&1 \
  && docker image inspect ghcr.io/zaproxy/zaproxy:stable >/dev/null 2>&1; then
  log "Utilisation de l'image ZAP deja presente"
  if docker run --rm --network host \
      -v "$OUTPUT_DIR:/zap/wrk:rw" \
      ghcr.io/zaproxy/zaproxy:stable \
      "$SCAN_SCRIPT" -t "$TARGET" "${EXTRA_ARGS[@]}" \
      -J zap-report.json -r zap-report.html \
      > "$OUTPUT_DIR/zap-console.log" 2>&1; then
    ok "Rapport ZAP Docker genere."
    exit 0
  fi
  warn "Le scan ZAP Docker a echoue."
fi

ZAP_CMD=""
for candidate in zaproxy zap.sh /usr/share/zaproxy/zap.sh; do
  if command -v "$candidate" >/dev/null 2>&1 || [[ -x "$candidate" ]]; then
    ZAP_CMD="$candidate"
    break
  fi
done

if [[ -z "$ZAP_CMD" ]]; then
  warn "ZAP non disponible. Installe zaproxy, zap-baseline.py ou l'image Docker officielle."
  exit 2
fi

PLAN="$OUTPUT_DIR/zap-plan.yaml"
python3 - "$TARGET" "$OUTPUT_DIR" "$PLAN" "$MODE" <<'PY'
import json
import sys
from pathlib import Path

target, output_dir, plan_path, mode = sys.argv[1:]
q = json.dumps
jobs = [
    '''  - type: spider
    parameters:
      context: "DevSecOps"
      maxDuration: 2''',
    '''  - type: passiveScan-wait
    parameters:
      maxDuration: 3''',
]
if mode == "active":
    jobs.append('''  - type: activeScan
    parameters:
      context: "DevSecOps"
      maxScanDurationInMins: 5''')
jobs.extend([
    f'''  - type: report
    parameters:
      template: "traditional-json"
      reportDir: {q(str(Path(output_dir).resolve()))}
      reportFile: "zap-report.json"''',
    f'''  - type: report
    parameters:
      template: "traditional-html"
      reportDir: {q(str(Path(output_dir).resolve()))}
      reportFile: "zap-report.html"''',
])
plan = f'''env:
  contexts:
    - name: "DevSecOps"
      urls:
        - {q(target)}
      includePaths:
        - {q(target + ".*")}
jobs:
''' + "\n".join(jobs) + "\n"
Path(plan_path).write_text(plan, encoding="utf-8")
PY

if "$ZAP_CMD" -cmd -autorun "$PLAN" > "$OUTPUT_DIR/zap-console.log" 2>&1; then
  ok "Rapport ZAP genere avec le framework d'automatisation."
  exit 0
fi

warn "ZAP n'a pas produit de rapport exploitable. Consulte zap-console.log."
exit 1
