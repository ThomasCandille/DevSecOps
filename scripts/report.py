#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}


def read_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def severity(value: Any) -> str:
    text = str(value or "info").lower().split()[0]
    aliases = {"informational": "info", "warning": "medium"}
    return aliases.get(text, text) if aliases.get(text, text) in SEVERITY_ORDER else "info"


def confidence(value: Any) -> str:
    text = str(value or "possible").lower()
    if "confirm" in text or text == "high":
        return "confirmed"
    if "probab" in text or text == "medium":
        return "probable"
    return "possible"


CONFIDENCE_ORDER = {"confirmed": 0, "probable": 1, "possible": 2}


def finding_family(title: str, category: str) -> str:
    value = f"{title} {category}".lower()
    if "sql" in value and ("inject" in value or "erreur" in value or "indice" in value):
        return "sql-injection-signal"
    if "redirection" in value or "redirect" in value:
        return "open-redirect"
    if "xss" in value or "reflech" in value or "reflet" in value:
        return "reflected-input"
    if "erreur serveur" in value and "entree" in value:
        return "input-server-error"
    return re.sub(r"\s+", " ", title).strip().lower()


def inferred_location(item: dict[str, Any]) -> tuple[str, str]:
    endpoint = str(item.get("endpoint") or item.get("url") or "").strip()
    parameter = str(item.get("parameter") or "").strip()
    evidence = str(item.get("evidence") or item.get("proof") or "")

    method_path = re.match(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/.+)$", endpoint, re.I)
    if method_path:
        endpoint = method_path.group(1)
    if not endpoint:
        match = re.search(r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(/[^\s;,]+)", evidence, re.I)
        if match:
            endpoint = match.group(1)
    if not parameter:
        patterns = (
            r"param(?:e|è)tre\s+([A-Za-z0-9_.-]+)",
            r"\bvia\s+([A-Za-z0-9_.-]+)",
            r"^([A-Za-z0-9_.-]+)\s+provoque\b",
        )
        for pattern in patterns:
            match = re.search(pattern, evidence, re.I)
            if match:
                parameter = match.group(1)
                break
    parameter = parameter.rstrip(".,;:")
    return endpoint.lower(), parameter.lower()


def finding_key(item: dict[str, Any]) -> tuple[str, str, str]:
    endpoint, parameter = inferred_location(item)
    return (
        finding_family(str(item.get("title") or item.get("alert") or ""), str(item.get("category") or "")),
        endpoint,
        parameter,
    )


def merge_findings(*collections: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for collection in collections:
        for raw in collection:
            if not isinstance(raw, dict):
                continue
            item = dict(raw)
            item["title"] = item.get("title") or item.get("alert") or "Constat sans titre"
            item["severity"] = severity(item.get("severity") or item.get("risk"))
            item["confidence"] = confidence(item.get("confidence"))
            item["category"] = item.get("category") or "Autre"
            item["tool"] = item.get("tool") or "Scanner"
            item["evidence"] = str(item.get("evidence") or item.get("proof") or "")[:1500]
            item["description"] = str(item.get("description") or item.get("desc") or "")[:2500]
            endpoint, parameter = inferred_location(item)
            if endpoint:
                item["endpoint"] = endpoint
            if parameter and not item.get("parameter"):
                item["parameter"] = parameter
            key = finding_key(item)
            family, endpoint_key, parameter_key = key
            if key not in merged and parameter_key:
                for existing_key in merged:
                    existing_family, existing_endpoint, existing_parameter = existing_key
                    if existing_family == family and existing_parameter == parameter_key and (
                        not endpoint_key or not existing_endpoint or endpoint_key == existing_endpoint
                    ):
                        key = existing_key
                        break
            if key not in merged:
                item["sources"] = [str(item["tool"])]
                item["evidence_items"] = [item["evidence"]] if item["evidence"] else []
                merged[key] = item
                continue

            current = merged[key]
            source = str(item["tool"])
            if source not in current.setdefault("sources", []):
                current["sources"].append(source)
            if SEVERITY_ORDER[item["severity"]] < SEVERITY_ORDER[current["severity"]]:
                current["severity"] = item["severity"]
                current["title"] = item["title"]
                current["category"] = item["category"]
                if item.get("description"):
                    current["description"] = item["description"]
            if CONFIDENCE_ORDER[item["confidence"]] < CONFIDENCE_ORDER[current["confidence"]]:
                current["confidence"] = item["confidence"]
                current["title"] = item["title"]
                current["category"] = item["category"]
                if item.get("description"):
                    current["description"] = item["description"]
            evidence_items = current.setdefault("evidence_items", [])
            if item["evidence"] and item["evidence"] not in evidence_items:
                evidence_items.append(item["evidence"])
            current["evidence"] = " | ".join(evidence_items[:3])[:1500]
            if not current.get("endpoint") and item.get("endpoint"):
                current["endpoint"] = item["endpoint"]
            if not current.get("parameter") and item.get("parameter"):
                current["parameter"] = item["parameter"]

    for item in merged.values():
        item.pop("evidence_items", None)
    return sorted(merged.values(), key=lambda item: (SEVERITY_ORDER[item["severity"]], str(item["title"]).lower()))


def list_of_dicts(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def extract_list(payload: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return list_of_dicts(value)
    return []


def parse_tool_status(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 2:
            rows.append({
                "tool": parts[0],
                "status": parts[1],
                "duration": parts[2] if len(parts) > 2 else "",
                "details": parts[3] if len(parts) > 3 else "",
            })
    return rows


def parse_zap(zap_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = read_json(zap_dir / "zap-report.json", {})
    alerts: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    sites = data.get("site", []) if isinstance(data, dict) else []
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites if isinstance(sites, list) else []:
        site_alerts = site.get("alerts", []) if isinstance(site, dict) else []
        if isinstance(site_alerts, dict):
            site_alerts = [site_alerts]
        for alert in site_alerts if isinstance(site_alerts, list) else []:
            if not isinstance(alert, dict):
                continue
            alerts.append(alert)
            instances = alert.get("instances", [])
            first = instances[0] if isinstance(instances, list) and instances else {}
            findings.append({
                "title": alert.get("alert") or alert.get("name") or "Alerte ZAP",
                "category": "OWASP ZAP",
                "severity": severity(alert.get("riskdesc") or alert.get("riskcode")),
                "confidence": confidence(alert.get("confidence")),
                "tool": "OWASP ZAP",
                "endpoint": first.get("uri", "") if isinstance(first, dict) else "",
                "parameter": first.get("param", "") if isinstance(first, dict) else "",
                "evidence": (first.get("evidence") or first.get("attack") or "")[:800] if isinstance(first, dict) else "",
                "description": str(alert.get("desc") or alert.get("solution") or "")[:1800],
            })
    return findings, alerts


def test_counts(items: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for item in items:
        result = str(item.get("result") or "executed")
        counts[result] += 1
    return counts


def coverage_row(name: str, status: str, tests: int, findings: int, note: str) -> dict[str, Any]:
    return {"name": name, "status": status, "tests": tests, "findings": findings, "note": note}


def build_report(root: Path) -> dict[str, Any]:
    meta_dir = root / "00-meta"
    static_dir = root / "02-static"
    dynamic_dir = root / "03-dynamic"
    auth_dir = root / "04-authentication"
    access_dir = root / "05-access-control"
    logic_dir = root / "06-business-logic"
    zap_dir = root / "07-zap"

    meta = read_json(meta_dir / "scan.json", {})
    static = read_json(static_dir / "static-analysis.json", {})
    if not static:
        static = read_json(static_dir / "raw-analysis.json", {})
    dynamic_findings = list_of_dicts(read_json(dynamic_dir / "dynamic-findings.json", []))
    auth_findings = list_of_dicts(read_json(auth_dir / "authentication-findings.json", []))
    access_findings = list_of_dicts(read_json(access_dir / "access-control-findings.json", []))
    logic_findings = list_of_dicts(read_json(logic_dir / "business-logic-findings.json", []))
    zap_findings, zap_alerts = parse_zap(zap_dir)

    static_findings = extract_list(static, "findings", "constats", "alerts")
    findings = merge_findings(static_findings, dynamic_findings, auth_findings, access_findings, logic_findings, zap_findings)

    endpoints = extract_list(static, "endpoints")
    confirmed = [item for item in endpoints if str(item.get("classification", "")).lower() == "confirmed"]
    candidates = [item for item in endpoints if str(item.get("classification", "")).lower() == "candidate"]
    if not endpoints:
        confirmed = extract_list(static, "confirmed_endpoints", "endpoints_confirmed")
        candidates = extract_list(static, "candidate_endpoints", "endpoints_candidates")

    static_parameters = extract_list(static, "parameters")
    dynamic_parameters = list_of_dicts(read_json(dynamic_dir / "dynamic-parameters.json", []))
    parameter_map: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for item in static_parameters + dynamic_parameters:
        key = (
            str(item.get("method") or "UNKNOWN"),
            str(item.get("path") or item.get("url") or ""),
            str(item.get("name") or ""),
            str(item.get("location") or "unknown"),
        )
        parameter_map[key] = item
    parameters = list(parameter_map.values())

    har_requests = list_of_dicts(read_json(dynamic_dir / "har-requests.json", []))
    dynamic_tests = list_of_dicts(read_json(dynamic_dir / "dynamic-tests.json", []))
    jwt_analysis = list_of_dicts(read_json(dynamic_dir / "jwt-analysis.json", []))
    auth_tests = list_of_dicts(read_json(auth_dir / "authentication-tests.json", []))
    access_tests = list_of_dicts(read_json(access_dir / "access-control-tests.json", []))
    logic_tests = list_of_dicts(read_json(logic_dir / "business-logic-tests.json", []))

    severity_counts = Counter(severity(item.get("severity")) for item in findings)
    coverage = [
        coverage_row("Reconnaissance et configuration", "executed" if static else "missing", len(confirmed) + len(candidates), len(static_findings), "WhatWeb, Nmap, Gobuster, Nikto, headers et cartographie statique."),
        coverage_row("Parametres et mutations", "executed" if dynamic_tests else ("inventory" if har_requests else "skipped"), len(dynamic_tests), len(dynamic_findings), "GET, formulaires et JSON observes dans un HAR."),
        coverage_row("Reflexion / XSS potentielle", "executed" if dynamic_tests else "skipped", len(dynamic_tests), sum(1 for item in dynamic_findings if "xss" in str(item.get("category", "")).lower() or "reflech" in str(item.get("title", "")).lower()), "Une reflexion reste a confirmer dans un navigateur."),
        coverage_row("Indices SQLi", "executed" if dynamic_tests else "skipped", len(dynamic_tests), sum(1 for item in dynamic_findings if "sql" in str(item.get("category", "")).lower() or "sql" in str(item.get("title", "")).lower()), "Detection d'erreurs et divergences, sans extraction de donnees."),
        coverage_row("Redirections ouvertes", "executed" if dynamic_tests else "skipped", len(dynamic_tests), sum(1 for item in dynamic_findings if "redirect" in str(item.get("category", "")).lower() or "redirection" in str(item.get("title", "")).lower()), "Redirections HTTP vers une origine externe fictive."),
        coverage_row("JWT", "executed" if jwt_analysis else "skipped", len(jwt_analysis), sum(1 for item in dynamic_findings if "jwt" in str(item.get("category", "")).lower()), "Analyse passive des metadonnees, sans conserver le token."),
        coverage_row("Authentification et anti-automation", "executed" if auth_tests else "skipped", len(auth_tests), len(auth_findings), "Enumeration limitee, limitation des tentatives et session apres logout."),
        coverage_row("Controle d'acces / BOLA", "executed" if access_tests else "skipped", len(access_tests), len(access_findings), "Comparaison de deux sessions et acces anonyme sur des ressources identifiees."),
        coverage_row("Logique metier", "executed" if logic_tests else "skipped", len(logic_tests), len(logic_findings), "Scenarios declaratifs propres a l'application."),
        coverage_row("OWASP ZAP", "executed" if zap_alerts or (zap_dir / "zap-report.json").exists() else "skipped", len(zap_alerts), len(zap_findings), f"Mode ZAP : {meta.get('zap_mode', 'off')}"),
    ]

    return {
        "version": "1.1.0",
        "scan": meta,
        "summary": {
            "findings": len(findings),
            "confirmed_endpoints": len(confirmed),
            "candidate_endpoints": len(candidates),
            "parameters": len(parameters),
            "har_requests": len(har_requests),
            "dynamic_tests": len(dynamic_tests),
            "authentication_tests": len(auth_tests),
            "access_control_tests": len(access_tests),
            "business_logic_tests": len(logic_tests),
            "jwt_tokens": len(jwt_analysis),
            "zap_alerts": len(zap_alerts),
            "severity": {name: severity_counts.get(name, 0) for name in ("critical", "high", "medium", "low", "info")},
        },
        "tool_status": parse_tool_status(meta_dir / "tool-status.tsv"),
        "coverage": coverage,
        "findings": findings,
        "confirmed_endpoints": confirmed,
        "candidate_endpoints": candidates,
        "parameters": parameters,
        "har_requests": har_requests,
        "dynamic_tests": dynamic_tests,
        "jwt_analysis": jwt_analysis,
        "authentication_tests": auth_tests,
        "access_control_tests": access_tests,
        "business_logic_tests": logic_tests,
        "zap_alerts": zap_alerts,
        "limitations": [
            "Aucun scanner automatise ne peut garantir l'absence de vulnerabilite.",
            "Les constats probables ou possibles necessitent une validation manuelle.",
            "Les scenarios de logique metier dependent de la configuration fournie pour l'application.",
            "Les tests de session peuvent invalider le compte de laboratoire utilise.",
            "Les fichiers HAR et configurations d'authentification peuvent contenir des secrets et ne doivent pas etre commits.",
        ],
    }


def badge(value: str) -> str:
    return f'<span class="badge severity-{esc(value)}">{esc(value)}</span>'


def table(headers: list[str], rows: list[list[Any]], empty: str) -> str:
    if not rows:
        return f'<p class="empty">{esc(empty)}</p>'
    head = "".join(f"<th>{esc(item)}</th>" for item in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(cell)}</td>" for cell in row) + "</tr>" for row in rows)
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html(report: dict[str, Any]) -> str:
    scan = report["scan"]
    summary = report["summary"]
    cards = [
        ("Constats", summary["findings"]),
        ("Endpoints confirmes", summary["confirmed_endpoints"]),
        ("Parametres", summary["parameters"]),
        ("Tests dynamiques", summary["dynamic_tests"]),
        ("Tests auth", summary["authentication_tests"]),
        ("Tests d'acces", summary["access_control_tests"]),
        ("Scenarios metier", summary["business_logic_tests"]),
        ("Alertes ZAP", summary["zap_alerts"]),
    ]
    cards_html = "".join(f'<div class="metric"><strong>{esc(value)}</strong><span>{esc(label)}</span></div>' for label, value in cards)
    risks_html = "".join(f'<div class="risk severity-{name}"><strong>{esc(summary["severity"][name])}</strong><span>{name}</span></div>' for name in ("critical", "high", "medium", "low", "info"))
    coverage_rows = [[item["name"], item["status"], item["tests"], item["findings"], item["note"]] for item in report["coverage"]]
    tool_rows = [[item["tool"], item["status"], item.get("duration", ""), item.get("details", "")] for item in report["tool_status"]]

    findings_html: list[str] = []
    for index, item in enumerate(report["findings"], 1):
        sources = ", ".join(item.get("sources", [item.get("tool", "Scanner")]))
        location = item.get("endpoint") or item.get("url") or ""
        parameter = item.get("parameter") or ""
        findings_html.append(f'''<article class="finding">
<div class="finding-title"><h3>{index}. {esc(item.get("title"))}</h3>{badge(item.get("severity", "info"))}</div>
<div class="meta"><span>{esc(item.get("category"))}</span><span>Confiance : {esc(item.get("confidence"))}</span><span>Sources : {esc(sources)}</span></div>
{f'<p><b>Emplacement :</b> {esc(location)} {esc(parameter)}</p>' if location or parameter else ''}
<p><b>Preuve :</b> {esc(item.get("evidence") or "Aucune preuve textuelle conservee.")}</p>
<p><b>Interpretation :</b> {esc(item.get("description") or "Validation manuelle recommandee.")}</p>
</article>''')

    confirmed_rows = [[item.get("method", "UNKNOWN"), item.get("path", ""), item.get("status", "-"), item.get("source", ""), item.get("sensitivity", "-")] for item in report["confirmed_endpoints"]]
    parameter_rows = [[item.get("method", "UNKNOWN"), item.get("path") or item.get("url", ""), item.get("name", ""), item.get("location", ""), item.get("source", "")] for item in report["parameters"]]
    jwt_rows = [[item.get("request_path", ""), item.get("source", ""), item.get("algorithm", ""), "oui" if item.get("has_exp") else "non", item.get("lifetime_seconds", "-")] for item in report["jwt_analysis"]]
    auth_rows = [[item.get("test_id", ""), item.get("result", ""), item.get("reason") or item.get("url") or item.get("probe_url") or ""] for item in report["authentication_tests"]]
    access_rows = [[item.get("test_id", ""), item.get("owner", ""), item.get("other_user", ""), item.get("url", ""), item.get("result", "")] for item in report["access_control_tests"]]
    logic_rows = [[item.get("scenario_id", ""), item.get("name", ""), item.get("result", ""), item.get("error") or ""] for item in report["business_logic_tests"]]
    limitations = "".join(f"<li>{esc(item)}</li>" for item in report["limitations"])

    return f'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Evaluation de securite {esc(scan.get('scan_id', ''))}</title>
<style>
:root{{--bg:#f4f6f8;--panel:#fff;--text:#18202a;--muted:#667085;--border:#dfe4ea}}*{{box-sizing:border-box}}body{{margin:0;font-family:Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}header{{background:#111827;color:#fff;padding:34px max(24px,calc((100% - 1180px)/2))}}header p{{margin:4px 0;color:#d1d5db}}main{{max-width:1180px;margin:24px auto;padding:0 20px 60px}}section{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:22px;margin-bottom:20px}}h2{{margin-top:0}}.metrics,.risks{{display:grid;grid-template-columns:repeat(auto-fit,minmax(145px,1fr));gap:12px}}.metric,.risk{{border:1px solid var(--border);border-radius:10px;padding:14px}}.metric strong,.risk strong{{display:block;font-size:1.7rem}}.metric span,.risk span{{color:var(--muted)}}.finding{{border:1px solid var(--border);border-radius:10px;padding:16px;margin:12px 0}}.finding-title{{display:flex;justify-content:space-between;gap:12px}}.finding h3{{margin:0}}.meta{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}}.meta span,.badge{{border-radius:999px;padding:4px 9px;background:#eef2f6;font-size:.86rem}}.badge{{color:#fff;font-weight:700;text-transform:uppercase}}.severity-critical{{background:#7a0019!important;color:#fff}}.severity-high{{background:#b42318!important;color:#fff}}.severity-medium{{background:#b54708!important;color:#fff}}.severity-low{{background:#175cd3!important;color:#fff}}.severity-info{{background:#475467!important;color:#fff}}.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}}th{{background:#f8fafc}}.empty{{color:var(--muted);font-style:italic}}code{{background:#edf1f4;padding:2px 5px;border-radius:4px}}
</style></head><body>
<header><h1>Evaluation de securite web — V1.1</h1><p><b>Cible :</b> {esc(scan.get('target'))}</p><p><b>Scan :</b> {esc(scan.get('scan_id'))} — <b>Mode :</b> {esc(scan.get('mode'))} — <b>Date UTC :</b> {esc(scan.get('started_at_utc'))}</p></header>
<main>
<section><h2>Resume</h2><div class="metrics">{cards_html}</div><div class="risks" style="margin-top:12px">{risks_html}</div></section>
<section><h2>Couverture reelle</h2>{table(['Domaine','Etat','Tests','Constats','Precision'], coverage_rows, 'Aucune information de couverture.')}</section>
<section><h2>Etat des outils</h2>{table(['Outil','Etat','Duree (s)','Details'], tool_rows, 'Aucun statut disponible.')}</section>
<section><h2>Constats consolides</h2>{''.join(findings_html) if findings_html else '<p class="empty">Aucun constat.</p>'}</section>
<section><h2>Endpoints confirmes</h2>{table(['Methode','Route','HTTP','Source','Sensibilite'], confirmed_rows, 'Aucun endpoint confirme.')}</section>
<section><h2>Parametres identifies</h2>{table(['Methode','Route','Parametre','Emplacement','Source'], parameter_rows, 'Aucun parametre fiable.')}</section>
<section><h2>JWT analyses</h2>{table(['Route','Source','Algorithme','Expiration','Duree (s)'], jwt_rows, 'Aucun JWT detecte.')}</section>
<section><h2>Authentification et session</h2>{table(['Test','Resultat','Contexte'], auth_rows, 'Aucun test d authentification execute.')}</section>
<section><h2>Controle d acces</h2>{table(['Test','Proprietaire','Autre session','Route','Resultat'], access_rows, 'Aucun test avec deux comptes execute.')}</section>
<section><h2>Logique metier</h2>{table(['Scenario','Nom','Resultat','Erreur'], logic_rows, 'Aucun scenario metier execute.')}</section>
<section><h2>Limites</h2><ul>{limitations}</ul></section>
</main></body></html>'''


def render_markdown(report: dict[str, Any]) -> str:
    scan = report["scan"]
    summary = report["summary"]
    lines = [
        "# Evaluation de securite web — V1.1", "",
        f"- **Cible :** `{scan.get('target', '')}`",
        f"- **Scan :** `{scan.get('scan_id', '')}`",
        f"- **Mode :** {scan.get('mode', '')}",
        f"- **Constats :** {summary['findings']}",
        f"- **Tests dynamiques :** {summary['dynamic_tests']}",
        f"- **Tests d'authentification :** {summary['authentication_tests']}",
        f"- **Tests de controle d'acces :** {summary['access_control_tests']}",
        f"- **Scenarios metier :** {summary['business_logic_tests']}", "",
        "## Couverture", "",
        "| Domaine | Etat | Tests | Constats |", "|---|---|---:|---:|",
    ]
    for item in report["coverage"]:
        lines.append(f"| {item['name']} | {item['status']} | {item['tests']} | {item['findings']} |")
    lines.extend(["", "## Constats", ""])
    if not report["findings"]:
        lines.append("Aucun constat.")
    for index, item in enumerate(report["findings"], 1):
        lines.extend([
            f"### {index}. {item.get('title')}",
            f"- Gravite : **{item.get('severity')}**",
            f"- Confiance : {item.get('confidence')}",
            f"- Categorie : {item.get('category')}",
            f"- Sources : {', '.join(item.get('sources', [item.get('tool', 'Scanner')]))}",
            f"- Preuve : {item.get('evidence') or 'Non conservee'}",
            f"- Interpretation : {item.get('description') or 'Validation manuelle recommandee'}", "",
        ])
    lines.extend(["## Limites", ""] + [f"- {item}" for item in report["limitations"]])
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generation du rapport consolide V1.1")
    parser.add_argument("--scan-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = args.scan_root.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = build_report(root)
    write_json(output / "security-assessment.json", report)
    (output / "security-assessment.html").write_text(render_html(report), encoding="utf-8")
    (output / "security-assessment.md").write_text(render_markdown(report), encoding="utf-8")
    print(f" [OK] Rapport principal genere : {output / 'security-assessment.html'}")


if __name__ == "__main__":
    main()
