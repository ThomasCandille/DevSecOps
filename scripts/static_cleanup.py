#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

VALID_STATUS = {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}
TRUSTED_SOURCES = {
    "html-crawl",
    "html-form",
    "gobuster",
    "robots.txt",
    "sitemap.xml",
    "global-profile",
}
CONTEXTUAL_JS_SOURCES = {
    "javascript-http",
    "javascript-url",
    "javascript-router",
}
NOISY_SOURCES = {"javascript-string"}
STATIC_EXTENSIONS = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".png",
    ".svg", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".json",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Segments autorises dans une route HTTP. Les espaces, accolades de code et
# fragments de traduction sont volontairement refuses.
SERVER_ROUTE_RE = re.compile(
    r"^/(?:[A-Za-z0-9._~!$&'()*+,;=:@%{}-]+/?)*"
    r"(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%{}\[\]/?:-]*)?$"
)
CLIENT_ROUTE_RE = re.compile(
    r"^/#/(?:[A-Za-z0-9._~!$&'()*+,;=:@%{}-]+/?)*"
    r"(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%{}\[\]/?:-]*)?$"
)
PARAMETER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,79}$")

BAD_ROUTE_FRAGMENTS = (
    "console.log", "stateNode", "containerInfo", "selkiesLogoAlt",
    "resolutionPresets", "binaryClipboard", "payload:{", "}},",
    "{title:", "{closeAlt:", "reactResources$", "varle=", "=>",
)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return default


def normalize_source(record: dict[str, Any]) -> str:
    source = str(record.get("source", "unknown"))
    if source.startswith("profile:"):
        return source
    return source


def is_profile_source(source: str) -> bool:
    return source.startswith("profile:")


def is_sane_route(path: str, kind: str) -> bool:
    if not path or len(path) > 240:
        return False
    if any(char.isspace() for char in path):
        return False
    lowered = path.lower()
    if any(fragment.lower() in lowered for fragment in BAD_ROUTE_FRAGMENTS):
        return False
    if path.count("{") != path.count("}"):
        return False
    if path.count("(") != path.count(")"):
        return False
    if "//" in path.replace("://", ""):
        return False
    pattern = CLIENT_ROUTE_RE if kind == "client" or path.startswith("/#/") else SERVER_ROUTE_RE
    return bool(pattern.fullmatch(path))


def endpoint_identity(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("method", "UNKNOWN")).upper(),
        str(record.get("path", "")),
        str(record.get("kind", "server")),
    )


def endpoint_decision(record: dict[str, Any]) -> tuple[str, str]:
    path = str(record.get("path", ""))
    kind = str(record.get("kind", "server"))
    source = normalize_source(record)
    status = record.get("status")
    accessible = record.get("accessible")
    spa_fallback = bool(record.get("spa_fallback"))

    if source in NOISY_SOURCES:
        return "rejected", "extraction JavaScript non contextuelle"
    if not is_sane_route(path, kind):
        return "rejected", "syntaxe de route invalide ou fragment de code"
    if spa_fallback:
        return "rejected", "reponse identique a la page generique de la SPA"
    if isinstance(status, int) and status == 404:
        return "rejected", "HTTP 404"
    if accessible is False and isinstance(status, int):
        return "rejected", f"HTTP {status} non concluant"

    # Une reponse valide, y compris 401/403, confirme vraisemblablement la route.
    if isinstance(status, int) and status in VALID_STATUS and accessible is not False:
        return "confirmed", f"route verifiee par HTTP {status}"

    # Les sources issues du HTML/Gobuster/robots/sitemap sont fiables, meme si
    # le rapport d'origine n'a pas recopie le statut dans l'endpoint.
    if source in TRUSTED_SOURCES or is_profile_source(source):
        return "candidate", "source fiable mais verification HTTP absente"

    # Un appel HTTP explicite dans le JavaScript est un bon candidat, mais n'est
    # confirme qu'apres une requete reelle.
    if source == "javascript-http":
        return "candidate", "appel HTTP explicite dans le JavaScript"

    if source in CONTEXTUAL_JS_SOURCES:
        return "candidate", "route extraite d'un contexte JavaScript"

    return "candidate", "source non confirmee"


def merge_endpoints(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for raw in records:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        key = endpoint_identity(record)
        source = normalize_source(record)
        if key not in merged:
            merged[key] = record
            merged[key]["sources"] = [source]
        else:
            current = merged[key]
            if source not in current["sources"]:
                current["sources"].append(source)
            for field in ("status", "accessible", "spa_fallback", "location", "content_type", "length"):
                if record.get(field) is not None:
                    current[field] = record[field]
            # On conserve la sensibilite la plus forte.
            if SEVERITY_ORDER.get(str(record.get("sensitivity", "low")), 9) < SEVERITY_ORDER.get(str(current.get("sensitivity", "low")), 9):
                current["sensitivity"] = record.get("sensitivity")
                current["category"] = record.get("category", current.get("category"))

    result: list[dict[str, Any]] = []
    for record in merged.values():
        classification, reason = endpoint_decision(record)
        record["classification"] = classification
        record["classification_reason"] = reason
        record["source"] = ", ".join(record.pop("sources", []))
        result.append(record)

    rank = {"confirmed": 0, "candidate": 1, "rejected": 2}
    return sorted(
        result,
        key=lambda item: (
            rank.get(str(item.get("classification")), 9),
            SEVERITY_ORDER.get(str(item.get("sensitivity", "low")), 9),
            str(item.get("path", "")),
        ),
    )


def finding_key(finding: dict[str, Any]) -> tuple[str, str, str]:
    title = str(finding.get("title", "")).lower()
    evidence = str(finding.get("evidence", "")).lower()
    category = str(finding.get("category", "")).lower()

    # Regroupe les alertes Nikto et internes concernant le meme header.
    header_match = re.search(
        r"(content-security-policy|x-content-type-options|referrer-policy|permissions-policy|strict-transport-security)",
        f"{title} {evidence}",
    )
    if header_match:
        return "header", header_match.group(1), category

    normalized_title = re.sub(r"\s+", " ", title).strip()
    normalized_evidence = re.sub(r"\s+", " ", evidence).strip()[:180]
    return normalized_title, category, normalized_evidence


def clean_findings(findings: Iterable[dict[str, Any]], target: str) -> list[dict[str, Any]]:
    scheme = urlsplit(target).scheme.lower()
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}

    for raw in findings:
        if not isinstance(raw, dict):
            continue
        finding = dict(raw)
        text = f"{finding.get('title', '')} {finding.get('evidence', '')}".lower()

        # HSTS n'est pertinent que pour HTTPS.
        if scheme != "https" and "strict-transport-security" in text:
            continue

        key = finding_key(finding)
        if key not in merged:
            finding["sources"] = [str(finding.get("tool", "unknown"))]
            merged[key] = finding
            continue

        current = merged[key]
        tool = str(finding.get("tool", "unknown"))
        if tool not in current["sources"]:
            current["sources"].append(tool)
        if SEVERITY_ORDER.get(str(finding.get("severity", "info")), 9) < SEVERITY_ORDER.get(str(current.get("severity", "info")), 9):
            current.update({
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "evidence": finding.get("evidence"),
                "description": finding.get("description", current.get("description", "")),
            })

    cleaned: list[dict[str, Any]] = []
    for finding in merged.values():
        finding["tool"] = ", ".join(finding.pop("sources", []))
        cleaned.append(finding)

    return sorted(
        cleaned,
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity", "info")), 9),
            str(item.get("title", "")),
        ),
    )


def clean_parameters(
    parameters: Iterable[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    accepted_paths = {
        str(item.get("path", "")).split("?", 1)[0]
        for item in endpoints
        if item.get("classification") in {"confirmed", "candidate"}
    }
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()

    for raw in parameters:
        if not isinstance(raw, dict):
            continue
        record = dict(raw)
        path = str(record.get("path", "")).split("?", 1)[0]
        name = str(record.get("name", ""))
        location = str(record.get("location", ""))
        method = str(record.get("method", "UNKNOWN")).upper()

        if path not in accepted_paths:
            continue
        if not PARAMETER_RE.fullmatch(name):
            continue
        if location not in {"query", "body", "path", "header", "cookie"}:
            continue

        key = (method, path, name, location)
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(record)

    return sorted(cleaned, key=lambda item: (str(item.get("path", "")), str(item.get("name", ""))))


def clean_sensitive_routes(
    sensitive_routes: Iterable[dict[str, Any]],
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    endpoint_map = {
        (str(item.get("path", "")), str(item.get("kind", "server"))): item
        for item in endpoints
    }
    cleaned: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for raw in sensitive_routes:
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path", ""))
        kind = str(raw.get("kind", "server"))
        endpoint = endpoint_map.get((path, kind))
        if not endpoint:
            continue
        if endpoint.get("classification") == "rejected":
            continue
        key = (path, kind)
        if key in seen:
            continue
        seen.add(key)
        record = dict(raw)
        record["classification"] = endpoint.get("classification")
        record["classification_reason"] = endpoint.get("classification_reason")
        record["status"] = endpoint.get("status", record.get("status"))
        record["accessible"] = endpoint.get("accessible", record.get("accessible"))
        cleaned.append(record)

    return sorted(
        cleaned,
        key=lambda item: (
            0 if item.get("classification") == "confirmed" else 1,
            SEVERITY_ORDER.get(str(item.get("sensitivity", "low")), 9),
            str(item.get("path", "")),
        ),
    )


def tool_status(directory: Path) -> list[dict[str, str]]:
    path = directory / "tool-status.tsv"
    if not path.exists():
        return []
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append({"tool": parts[0], "status": parts[1]})
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Nettoie et consolide les donnees statiques du scanner DevSecOps.")
    parser.add_argument("--input", required=True, type=Path, help="Dossier de cartographie statique")
    args = parser.parse_args()
    directory = args.input.resolve()

    raw_report = load_json(directory / "raw-analysis.json", {})
    if not isinstance(raw_report, dict) or not raw_report:
        raise SystemExit(f"raw-analysis.json introuvable ou invalide dans {directory}")

    raw_endpoints = raw_report.get("endpoints")
    if not isinstance(raw_endpoints, list):
        raw_endpoints = load_json(directory / "endpoints.json", [])
    raw_parameters = raw_report.get("parameters")
    if not isinstance(raw_parameters, list):
        parameter_file = load_json(directory / "parameters.json", {})
        raw_parameters = parameter_file.get("parameters", []) if isinstance(parameter_file, dict) else []
    raw_sensitive = raw_report.get("sensitive_routes", [])
    raw_findings = raw_report.get("findings", [])
    active_tests = raw_report.get("active_tests")
    if not isinstance(active_tests, list):
        active_tests = load_json(directory / "active-tests.json", [])

    target = str(raw_report.get("target", ""))
    endpoints = merge_endpoints(raw_endpoints if isinstance(raw_endpoints, list) else [])
    parameters = clean_parameters(raw_parameters if isinstance(raw_parameters, list) else [], endpoints)
    findings = clean_findings(raw_findings if isinstance(raw_findings, list) else [], target)
    sensitive_routes = clean_sensitive_routes(raw_sensitive if isinstance(raw_sensitive, list) else [], endpoints)

    classification_counts = Counter(str(item.get("classification")) for item in endpoints)
    payload = {
        "version": "1.1.0-static-cleaner",
        "source_report_version": raw_report.get("version"),
        "target": target,
        "mode": raw_report.get("mode", "unknown"),
        "profiles": raw_report.get("profiles", []),
        "tool_status": tool_status(directory),
        "summary": {
            "finding_count": len(findings),
            "confirmed_endpoint_count": classification_counts.get("confirmed", 0),
            "candidate_endpoint_count": classification_counts.get("candidate", 0),
            "rejected_endpoint_count": classification_counts.get("rejected", 0),
            "parameter_count": len(parameters),
            "sensitive_route_count": len(sensitive_routes),
            "active_test_count": len(active_tests),
        },
        "findings": findings,
        "sensitive_routes": sensitive_routes,
        "endpoints": endpoints,
        "parameters": parameters,
        "active_tests": active_tests,
    }

    output = directory / "static-analysis.json"
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f" [OK] Donnees statiques consolidees : {output}")
    print(
        "      Resume : "
        f"{len(findings)} constat(s), "
        f"{classification_counts.get('confirmed', 0)} endpoint(s) confirme(s), "
        f"{classification_counts.get('candidate', 0)} candidat(s), "
        f"{classification_counts.get('rejected', 0)} element(s) filtre(s)."
    )


if __name__ == "__main__":
    main()
