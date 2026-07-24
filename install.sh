#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

printf '[INFO] Preparation de DevSecOps Scanner V1.1 dans %s\n' "$PROJECT_DIR"
chmod +x "$PROJECT_DIR/scan.sh" "$PROJECT_DIR/install.sh" "$PROJECT_DIR/scripts/"*.py "$PROJECT_DIR/scripts/"*.sh
mkdir -p "$PROJECT_DIR/results"
touch "$PROJECT_DIR/results/.gitkeep"

python3 "$PROJECT_DIR/scripts/self_check.py" --project "$PROJECT_DIR"
python3 -m unittest discover -s "$PROJECT_DIR/tests" -p 'test_*.py'

printf '\n[OK] Installation locale terminee.\n'
printf 'Commande de verification : ./scan.sh --check\n'
printf 'Commande minimale : ./scan.sh http://127.0.0.1:3000\n'
printf '\nOutils Kali optionnels recommandes : whatweb nmap gobuster nikto zaproxy\n'
printf 'Ils ne sont pas installes automatiquement afin de ne pas modifier le systeme sans accord.\n'
