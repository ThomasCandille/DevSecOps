#!/usr/bin/env python3
"""Verifie l'integrite locale du projet et la disponibilite des outils."""

from __future__ import annotations

import argparse
import json
import py_compile
import shutil
import sys
from pathlib import Path
from typing import Any

REQUIRED_FILES = (
    "scan.sh",
    "scripts/analyse.py",
    "scripts/discovery.py",
    "scripts/har_active.py",
    "scripts/auth_logic.py",
    "scripts/static_cleanup.py",
    "scripts/report.py",
    "scripts/zap_scan.sh",
    "config/sensitive-paths.txt",
)
REQUIRED_COMMANDS = ("python3", "curl")
OPTIONAL_COMMANDS = ("whatweb", "nmap", "gobuster", "nikto", "zaproxy", "docker")
JSON_FILES = (
    "config/auth-tests.example.json",
    "config/business-scenarios.example.json",
)


def check(project: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    files: dict[str, str] = {}
    commands: dict[str, str] = {}

    for relative in REQUIRED_FILES:
        path = project / relative
        files[relative] = "ok" if path.is_file() else "missing"
        if not path.is_file():
            errors.append(f"Fichier requis absent : {relative}")

    for relative in JSON_FILES:
        path = project / relative
        if not path.is_file():
            errors.append(f"Configuration exemple absente : {relative}")
            continue
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"JSON invalide dans {relative} : {error}")

    for relative in ("scripts/analyse.py", "scripts/discovery.py", "scripts/har_active.py", "scripts/auth_logic.py", "scripts/static_cleanup.py", "scripts/report.py", "scripts/self_check.py"):
        path = project / relative
        if not path.is_file():
            continue
        try:
            py_compile.compile(str(path), doraise=True)
        except py_compile.PyCompileError as error:
            errors.append(f"Erreur Python dans {relative} : {error.msg}")

    for command in REQUIRED_COMMANDS:
        found = shutil.which(command)
        commands[command] = found or "missing"
        if not found:
            errors.append(f"Commande requise absente : {command}")

    for command in OPTIONAL_COMMANDS:
        found = shutil.which(command)
        commands[command] = found or "missing"
        if not found:
            warnings.append(f"Outil optionnel absent : {command}")

    return {
        "project": str(project),
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "files": files,
        "commands": commands,
        "python": sys.version.split()[0],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Auto-diagnostic DevSecOps Scanner V1.1")
    parser.add_argument("--project", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--json", action="store_true", dest="as_json")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    result = check(args.project.resolve())
    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print("[CHECK] DevSecOps Scanner V1.1")
        for error in result["errors"]:
            print(f"[ERROR] {error}")
        for warning in result["warnings"]:
            print(f"[WARN] {warning}")
        if result["ok"]:
            print("[OK] Integrite du projet validee.")
        else:
            print("[ERROR] Le projet contient des erreurs bloquantes.")

    raise SystemExit(0 if result["ok"] else 1)


if __name__ == "__main__":
    main()
