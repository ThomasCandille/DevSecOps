#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${1:-$(pwd)}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "$PROJECT_DIR/scan.sh" || ! -f "$PROJECT_DIR/scripts/analyse.py" ]]; then
  echo "Erreur : lance ce script depuis la racine du projet DevSecOps"
  echo "ou indique son chemin : ./install.sh /chemin/vers/DevSecOps"
  exit 1
fi

mkdir -p "$PROJECT_DIR/scripts"
cp "$SOURCE_DIR/scripts/report_clean.py" "$PROJECT_DIR/scripts/report_clean.py"
chmod +x "$PROJECT_DIR/scripts/report_clean.py"

python3 - "$PROJECT_DIR/scan.sh" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

call = '''\npython3 "$SCRIPT_DIR/scripts/report_clean.py" \\\n  --input "$OUTPUT_DIR"\n'''

if 'scripts/report_clean.py' in text:
    print("[OK] scan.sh appelle deja report_clean.py")
    raise SystemExit(0)

needle = '''python3 "$SCRIPT_DIR/scripts/analyse.py" \\\n  --target "$TARGET" \\\n  --input "$OUTPUT_DIR" \\\n  --mode "$MODE" \\\n  --profile "$PROFILE"\n'''

if needle not in text:
    raise SystemExit(
        "Impossible de trouver l'appel a analyse.py dans scan.sh. "
        "Ajoute manuellement l'appel a report_clean.py apres analyse.py."
    )

text = text.replace(needle, needle + call, 1)
path.write_text(text, encoding="utf-8")
print("[OK] scan.sh mis a jour")
PY

python3 -m py_compile "$PROJECT_DIR/scripts/report_clean.py"
echo "[OK] Correctif installe. Le prochain scan generera report-clean.html."
