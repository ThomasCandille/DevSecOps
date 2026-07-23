#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
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


def e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def badge(value: str) -> str:
    value = value.lower()
    return f'<span class="badge badge-{e(value)}">{e(value)}</span>'


def render_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<p class="empty">Aucun constat consolide.</p>'
    cards = []
    for index, item in enumerate(findings, start=1):
        cards.append(
            f"""
            <article class="finding">
              <div class="finding-head"><h3>{index}. {e(item.get('title'))}</h3>{badge(str(item.get('severity', 'info')))}</div>
              <dl>
                <dt>Categorie</dt><dd>{e(item.get('category'))}</dd>
                <dt>Confiance</dt><dd>{e(item.get('confidence'))}</dd>
                <dt>Sources</dt><dd>{e(item.get('tool'))}</dd>
                <dt>Preuve</dt><dd><code>{e(item.get('evidence'))}</code></dd>
                <dt>Interpretation</dt><dd>{e(item.get('description'))}</dd>
              </dl>
            </article>
            """
        )
    return "".join(cards)


def render_endpoint_rows(endpoints: list[dict[str, Any]]) -> str:
    if not endpoints:
        return '<tr><td colspan="8" class="empty">Aucune route dans cette categorie.</td></tr>'
    rows = []
    for item in endpoints:
        status = item.get("status") if item.get("status") is not None else "-"
        rows.append(
            "<tr>"
            f"<td>{e(item.get('method', 'UNKNOWN'))}</td>"
            f"<td><code>{e(item.get('path'))}</code></td>"
            f"<td>{e(item.get('kind', 'server'))}</td>"
            f"<td>{e(item.get('category', 'Application'))}</td>"
            f"<td>{badge(str(item.get('sensitivity', 'low')))}</td>"
            f"<td>{e(status)}</td>"
            f"<td>{e(item.get('source'))}</td>"
            f"<td>{e(item.get('classification_reason'))}</td>"
            "</tr>"
        )
    return "".join(rows)


def render_parameter_rows(parameters: list[dict[str, Any]]) -> str:
    if not parameters:
        return '<tr><td colspan="6" class="empty">Aucun parametre fiable decouvert.</td></tr>'
    rows = []
    for item in parameters:
        rows.append(
            "<tr>"
            f"<td>{e(item.get('method'))}</td>"
            f"<td><code>{e(item.get('path'))}</code></td>"
            f"<td><code>{e(item.get('name'))}</code></td>"
            f"<td>{e(item.get('location'))}</td>"
            f"<td>{e(item.get('source'))}</td>"
            f"<td>{'oui' if item.get('active_testable') else 'non'}</td>"
            "</tr>"
        )
    return "".join(rows)


def write_html(directory: Path, report: dict[str, Any]) -> None:
    endpoints = report["endpoints"]
    confirmed = [item for item in endpoints if item.get("classification") == "confirmed"]
    candidates = [item for item in endpoints if item.get("classification") == "candidate"]
    rejected = [item for item in endpoints if item.get("classification") == "rejected"]
    severity_counts = Counter(str(item.get("severity", "info")) for item in report["findings"])
    statuses = report.get("tool_status", [])

    status_rows = "".join(
        f"<tr><td>{e(row['tool'])}</td><td>{badge(row['status'])}</td></tr>" for row in statuses
    ) or '<tr><td colspan="2" class="empty">Etat des outils indisponible.</td></tr>'

    severity_summary = "".join(
        f'<div class="metric"><strong>{severity_counts.get(level, 0)}</strong><span>{e(level)}</span></div>'
        for level in ("critical", "high", "medium", "low", "info")
    )

    profile_text = ", ".join(report.get("profiles", [])) or "global uniquement"
    active_tests = report.get("active_tests", [])

    document = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport consolide - {e(report.get('target'))}</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, Arial, sans-serif; --border:#d9dee7; --muted:#667085; --bg:#f5f7fa; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; background:var(--bg); color:#172033; line-height:1.45; }}
    main {{ max-width:1280px; margin:0 auto; padding:32px 22px 60px; }}
    header, section {{ background:#fff; border:1px solid var(--border); border-radius:14px; padding:22px; margin-bottom:18px; }}
    h1 {{ margin:0 0 8px; font-size:28px; }} h2 {{ margin-top:0; font-size:21px; }} h3 {{ margin:0; font-size:17px; }}
    .muted {{ color:var(--muted); }}
    .metrics {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:10px; margin-top:18px; }}
    .metric {{ border:1px solid var(--border); border-radius:10px; padding:14px; display:flex; flex-direction:column; }}
    .metric strong {{ font-size:24px; }} .metric span {{ color:var(--muted); text-transform:uppercase; font-size:12px; }}
    .finding {{ border:1px solid var(--border); border-radius:10px; padding:16px; margin:12px 0; }}
    .finding-head {{ display:flex; justify-content:space-between; gap:10px; align-items:center; }}
    dl {{ display:grid; grid-template-columns:130px 1fr; gap:6px 12px; margin-bottom:0; }} dt {{ font-weight:700; }} dd {{ margin:0; overflow-wrap:anywhere; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }} th, td {{ text-align:left; border-bottom:1px solid var(--border); padding:10px 8px; vertical-align:top; }} th {{ background:#f8fafc; position:sticky; top:0; }}
    .table-wrap {{ overflow:auto; max-height:620px; border:1px solid var(--border); border-radius:10px; }}
    code {{ background:#f1f4f8; padding:2px 5px; border-radius:4px; overflow-wrap:anywhere; }}
    .badge {{ display:inline-block; border-radius:999px; padding:3px 9px; font-size:12px; font-weight:700; white-space:nowrap; background:#edf1f7; }}
    .badge-critical,.badge-failed {{ background:#fee4e2; color:#b42318; }}
    .badge-high {{ background:#ffead5; color:#b54708; }}
    .badge-medium {{ background:#fef0c7; color:#b54708; }}
    .badge-low {{ background:#e0f2fe; color:#026aa2; }}
    .badge-info,.badge-success {{ background:#dcfae6; color:#067647; }}
    .badge-missing {{ background:#f2f4f7; color:#475467; }}
    details {{ margin-top:10px; }} summary {{ cursor:pointer; font-weight:700; }} .empty {{ color:var(--muted); text-align:center; }}
    .notice {{ border-left:4px solid #6172f3; padding:10px 14px; background:#eef4ff; }}
  </style>
</head>
<body><main>
<header>
  <h1>Rapport consolide du scan</h1>
  <p><strong>Cible :</strong> <code>{e(report.get('target'))}</code><br>
  <strong>Mode :</strong> {e(report.get('mode'))} — <strong>Profil :</strong> {e(profile_text)}</p>
  <p class="notice">Ce rapport distingue les routes confirmees des simples candidates. Les fragments de code JavaScript et les reponses 404/SPA generiques sont exclus du resume principal.</p>
  <div class="metrics">
    <div class="metric"><strong>{len(report['findings'])}</strong><span>constats consolides</span></div>
    <div class="metric"><strong>{len(confirmed)}</strong><span>endpoints confirmes</span></div>
    <div class="metric"><strong>{len(candidates)}</strong><span>routes candidates</span></div>
    <div class="metric"><strong>{len(report['parameters'])}</strong><span>parametres fiables</span></div>
    <div class="metric"><strong>{len(active_tests)}</strong><span>tests actifs</span></div>
  </div>
  <div class="metrics">{severity_summary}</div>
</header>
<section><h2>Etat des outils</h2><div class="table-wrap"><table><thead><tr><th>Outil</th><th>Etat</th></tr></thead><tbody>{status_rows}</tbody></table></div></section>
<section><h2>Constats</h2>{render_findings(report['findings'])}</section>
<section><h2>Endpoints confirmes</h2><p class="muted">Routes ayant obtenu une reponse HTTP concluante et differente d'une page generique.</p><div class="table-wrap"><table><thead><tr><th>Methode</th><th>Route</th><th>Type</th><th>Categorie</th><th>Sensibilite</th><th>HTTP</th><th>Source</th><th>Justification</th></tr></thead><tbody>{render_endpoint_rows(confirmed)}</tbody></table></div></section>
<section><h2>Routes candidates</h2><p class="muted">Indices plausibles qui necessitent encore une verification HTTP ou une navigation reelle.</p><div class="table-wrap"><table><thead><tr><th>Methode</th><th>Route</th><th>Type</th><th>Categorie</th><th>Sensibilite</th><th>HTTP</th><th>Source</th><th>Justification</th></tr></thead><tbody>{render_endpoint_rows(candidates)}</tbody></table></div></section>
<section><h2>Parametres fiables</h2><div class="table-wrap"><table><thead><tr><th>Methode</th><th>Route</th><th>Parametre</th><th>Emplacement</th><th>Source</th><th>Test actif</th></tr></thead><tbody>{render_parameter_rows(report['parameters'])}</tbody></table></div></section>
<section><h2>Tests actifs</h2><p>{len(active_tests)} parametre(s) ou scenario(s) testes. Les details complets restent disponibles dans <code>active-tests.json</code>.</p></section>
<section><h2>Limites</h2><ul><li>La cartographie statique ne remplace pas un navigateur executant JavaScript.</li><li>Les formulaires POST, sessions authentifiees, controles d'acces et logiques metier requierent une validation dediee.</li><li>Une route candidate ne doit jamais etre presentee comme une vulnerabilite confirmee.</li></ul>
<details><summary>Routes rejetees et bruit filtre ({len(rejected)})</summary><div class="table-wrap"><table><thead><tr><th>Methode</th><th>Route</th><th>Type</th><th>Categorie</th><th>Sensibilite</th><th>HTTP</th><th>Source</th><th>Motif du rejet</th></tr></thead><tbody>{render_endpoint_rows(rejected)}</tbody></table></div></details></section>
</main></body></html>"""
    (directory / "report-clean.html").write_text(document, encoding="utf-8")


def write_markdown(directory: Path, report: dict[str, Any]) -> None:
    endpoints = report["endpoints"]
    confirmed = [item for item in endpoints if item.get("classification") == "confirmed"]
    candidates = [item for item in endpoints if item.get("classification") == "candidate"]
    rejected = [item for item in endpoints if item.get("classification") == "rejected"]
    profile_text = ", ".join(report.get("profiles", [])) or "global uniquement"

    lines = [
        "# Rapport consolide du scan",
        "",
        f"- **Cible :** `{report.get('target', '')}`",
        f"- **Mode :** {report.get('mode', '')}",
        f"- **Profil :** {profile_text}",
        f"- **Constats consolides :** {len(report['findings'])}",
        f"- **Endpoints confirmes :** {len(confirmed)}",
        f"- **Routes candidates :** {len(candidates)}",
        f"- **Routes rejetees :** {len(rejected)}",
        f"- **Parametres fiables :** {len(report['parameters'])}",
        f"- **Tests actifs :** {len(report.get('active_tests', []))}",
        "",
        "> Les routes candidates et rejetees ne sont pas comptees comme des vulnerabilites confirmees.",
        "",
        "## Constats",
        "",
    ]

    if not report["findings"]:
        lines.append("Aucun constat consolide.")
    for index, item in enumerate(report["findings"], start=1):
        lines.extend([
            f"### {index}. {item.get('title', '')}",
            "",
            f"- Gravite : **{item.get('severity', 'info')}**",
            f"- Categorie : {item.get('category', '')}",
            f"- Confiance : {item.get('confidence', '')}",
            f"- Sources : {item.get('tool', '')}",
            f"- Preuve : `{item.get('evidence', '')}`",
            f"- Interpretation : {item.get('description', '')}",
            "",
        ])

    def endpoint_table(title: str, rows: list[dict[str, Any]]) -> None:
        lines.extend([f"## {title}", "", "| Methode | Route | HTTP | Source | Justification |", "|---|---|---:|---|---|"])
        if not rows:
            lines.append("| - | Aucune | - | - | - |")
        for item in rows:
            lines.append(
                f"| {item.get('method', 'UNKNOWN')} | `{item.get('path', '')}` | "
                f"{item.get('status', '-') if item.get('status') is not None else '-'} | "
                f"{item.get('source', '')} | {item.get('classification_reason', '')} |"
            )
        lines.append("")

    endpoint_table("Endpoints confirmes", confirmed)
    endpoint_table("Routes candidates", candidates)

    lines.extend(["## Parametres fiables", "", "| Methode | Route | Parametre | Emplacement | Test actif |", "|---|---|---|---|---|"])
    if not report["parameters"]:
        lines.append("| - | Aucune | - | - | - |")
    for item in report["parameters"]:
        lines.append(
            f"| {item.get('method', '')} | `{item.get('path', '')}` | `{item.get('name', '')}` | "
            f"{item.get('location', '')} | {'oui' if item.get('active_testable') else 'non'} |"
        )

    lines.extend([
        "",
        "## Limites",
        "",
        "- Une route candidate ne constitue pas une vulnerabilite confirmee.",
        "- Les routes authentifiees, POST et la logique metier demandent une validation manuelle ou un import HAR.",
        "- Les routes rejetees restent conservees dans `report-clean.json` pour audit.",
    ])
    (directory / "report-clean.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Nettoie et consolide le rapport du scanner DevSecOps.")
    parser.add_argument("--input", required=True, type=Path, help="Dossier results/AAAA-MM-JJ_HH-MM-SS")
    args = parser.parse_args()
    directory = args.input.resolve()

    raw_report = load_json(directory / "report.json", {})
    if not isinstance(raw_report, dict) or not raw_report:
        raise SystemExit(f"report.json introuvable ou invalide dans {directory}")

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
        "version": "0.5.0-report-cleaner",
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

    (directory / "report-clean.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_markdown(directory, payload)
    write_html(directory, payload)

    print(" [OK] Rapport consolide genere :")
    print(f"      - {directory / 'report-clean.html'}")
    print(f"      - {directory / 'report-clean.md'}")
    print(f"      - {directory / 'report-clean.json'}")
    print(
        "      Resume : "
        f"{len(findings)} constat(s), "
        f"{classification_counts.get('confirmed', 0)} endpoint(s) confirme(s), "
        f"{classification_counts.get('candidate', 0)} candidat(s), "
        f"{classification_counts.get('rejected', 0)} element(s) filtre(s)."
    )


if __name__ == "__main__":
    main()
