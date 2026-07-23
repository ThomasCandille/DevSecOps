#!/usr/bin/env python3

from __future__ import annotations

import argparse
import html
import json
import re
import ssl
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

MAX_JS_FILES = 30
MAX_JS_SIZE = 5_000_000
USER_AGENT = "WebSecurityScanner-MVP/0.2"

SECURITY_HEADERS = {
    "content-security-policy": (
        "Content-Security-Policy absent",
        "low",
        "Peut augmenter l'impact de certaines injections cote navigateur.",
    ),
    "x-content-type-options": (
        "X-Content-Type-Options absent",
        "low",
        "Le navigateur peut interpreter un contenu avec un type inattendu.",
    ),
    "referrer-policy": (
        "Referrer-Policy absent",
        "low",
        "Des informations d'URL peuvent etre transmises a d'autres sites.",
    ),
    "permissions-policy": (
        "Permissions-Policy absent",
        "info",
        "Les fonctions du navigateur ne sont pas explicitement restreintes.",
    ),
}

ROUTE_PATTERNS = [
    re.compile(r"[\"']((?:/|https?://)[^\"'\s]{1,300})[\"']"),
    re.compile(r"(?:url|endpoint|path)\s*:\s*[\"']([^\"']+)[\"']", re.I),
]

INTERESTING_ROUTE_MARKERS = (
    "/api/",
    "/rest/",
    "/admin",
    "/internal",
    "/auth",
    "/login",
    "/user",
    "/account",
    "/search",
    "/files",
)

SENSITIVE_JS_PATTERNS = {
    "Stockage local utilise": re.compile(r"\blocalStorage\b"),
    "Stockage de session utilise": re.compile(r"\bsessionStorage\b"),
    "Jeton d'autorisation mentionne": re.compile(r"\b(?:Authorization|Bearer)\b", re.I),
    "Secret potentiel mentionne": re.compile(
        r"\b(?:api[_-]?key|secret|password|token)\b\s*[:=]", re.I
    ),
}


class ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = dict(attrs)
        source = attributes.get("src")
        if source:
            self.scripts.append(source)


@dataclass
class HeaderResponse:
    status_line: str
    headers: dict[str, list[str]]


def log(message: str) -> None:
    print(f"      -> {message}")


def log_ok(message: str) -> None:
    print(f"      [OK] {message}")


def log_warn(message: str) -> None:
    print(f"      [!] {message}")


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def parse_last_header_block(content: str) -> HeaderResponse:
    blocks = [block for block in re.split(r"\r?\n\r?\n", content) if block.strip()]
    final_block = blocks[-1] if blocks else content
    lines = final_block.splitlines()
    status_line = lines[0].strip() if lines else ""
    headers: dict[str, list[str]] = {}

    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())

    return HeaderResponse(status_line=status_line, headers=headers)


def first_header(response: HeaderResponse, name: str) -> str:
    values = response.headers.get(name.lower(), [])
    return values[0] if values else ""


def add_finding(
    findings: list[dict[str, Any]],
    *,
    title: str,
    category: str,
    severity: str,
    confidence: str,
    tool: str,
    evidence: str,
    description: str,
) -> None:
    findings.append(
        {
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "tool": tool,
            "evidence": evidence.strip(),
            "description": description,
        }
    )


def analyse_headers(directory: Path, findings: list[dict[str, Any]]) -> None:
    log("Analyse des headers de securite")
    content = read_text(directory / "headers.txt")
    if not content:
        log_warn("Aucun header HTTP disponible.")
        return

    response = parse_last_header_block(content)

    for name, (title, severity, description) in SECURITY_HEADERS.items():
        if name not in response.headers:
            add_finding(
                findings,
                title=title,
                category="Security Misconfiguration",
                severity=severity,
                confidence="confirmed",
                tool="HTTP headers",
                evidence=f"Header {name} absent de la reponse finale.",
                description=description,
            )

    server = first_header(response, "server")
    if server:
        add_finding(
            findings,
            title="Technologie serveur exposee",
            category="Information Disclosure",
            severity="info",
            confidence="confirmed",
            tool="HTTP headers",
            evidence=f"Server: {server}",
            description="Le header Server fournit une information utile a la reconnaissance.",
        )

    powered_by = first_header(response, "x-powered-by")
    if powered_by:
        add_finding(
            findings,
            title="Framework serveur expose",
            category="Information Disclosure",
            severity="info",
            confidence="confirmed",
            tool="HTTP headers",
            evidence=f"X-Powered-By: {powered_by}",
            description="Ce header divulgue une technologie utilisee par l'application.",
        )

    log_ok("Headers analyses.")


def split_set_cookie(value: str) -> tuple[str, set[str]]:
    parts = [part.strip() for part in value.split(";") if part.strip()]
    name = parts[0].split("=", 1)[0] if parts else "cookie"
    attributes = {part.split("=", 1)[0].lower() for part in parts[1:]}
    return name, attributes


def analyse_cookies(directory: Path, findings: list[dict[str, Any]]) -> None:
    log("Analyse des cookies")
    response = parse_last_header_block(read_text(directory / "headers.txt"))
    cookies = response.headers.get("set-cookie", [])

    if not cookies:
        log_ok("Aucun cookie defini par la page principale.")
        return

    for cookie in cookies:
        name, attributes = split_set_cookie(cookie)
        masked = f"{name}=<masque>"

        if "httponly" not in attributes:
            add_finding(
                findings,
                title=f"Cookie {name} sans HttpOnly",
                category="Session Management",
                severity="medium",
                confidence="confirmed",
                tool="HTTP cookies",
                evidence=f"{masked}; attribut HttpOnly absent",
                description="Le cookie pourrait etre accessible a un script execute dans la page.",
            )
        if "samesite" not in attributes:
            add_finding(
                findings,
                title=f"Cookie {name} sans SameSite",
                category="Session Management",
                severity="low",
                confidence="confirmed",
                tool="HTTP cookies",
                evidence=f"{masked}; attribut SameSite absent",
                description="Le cookie ne declare pas explicitement sa politique intersite.",
            )
        if "secure" not in attributes:
            add_finding(
                findings,
                title=f"Cookie {name} sans Secure",
                category="Session Management",
                severity="low",
                confidence="confirmed",
                tool="HTTP cookies",
                evidence=f"{masked}; attribut Secure absent",
                description="Le cookie peut etre transmis sur une connexion HTTP non chiffree.",
            )

    log_ok(f"{len(cookies)} cookie(s) analyse(s).")


def analyse_options(directory: Path, findings: list[dict[str, Any]]) -> None:
    log("Analyse des methodes HTTP")
    response = parse_last_header_block(read_text(directory / "options-headers.txt"))
    allowed = first_header(response, "allow") or first_header(response, "access-control-allow-methods")

    if not allowed:
        log_ok("Aucune liste de methodes annoncee.")
        return

    methods = {method.strip().upper() for method in allowed.split(",")}
    risky = sorted(methods.intersection({"PUT", "DELETE", "PATCH", "TRACE"}))
    if risky:
        add_finding(
            findings,
            title="Methodes HTTP sensibles annoncees",
            category="Security Misconfiguration",
            severity="info",
            confidence="possible",
            tool="HTTP OPTIONS",
            evidence=f"Methodes annoncees : {', '.join(sorted(methods))}",
            description="Leur presence n'est pas une faille en soi ; leur controle d'acces doit etre verifie.",
        )
    log_ok(f"Methodes annoncees : {', '.join(sorted(methods))}")


def analyse_cors(directory: Path, findings: list[dict[str, Any]]) -> None:
    log("Analyse de la politique CORS")
    response = parse_last_header_block(read_text(directory / "cors-headers.txt"))
    origin = first_header(response, "access-control-allow-origin")
    credentials = first_header(response, "access-control-allow-credentials").lower()

    if not origin:
        log_ok("Aucune autorisation CORS retournee pour l'origine de test.")
        return

    severity = "medium" if credentials == "true" else "low"
    add_finding(
        findings,
        title="Politique CORS permissive potentielle",
        category="Security Misconfiguration",
        severity=severity,
        confidence="possible",
        tool="HTTP CORS",
        evidence=f"Access-Control-Allow-Origin: {origin}; credentials: {credentials or 'non'}",
        description="La sensibilite depend des donnees exposees et de l'utilisation des identifiants.",
    )
    log_warn(f"Origine autorisee retournee : {origin}")


def analyse_nmap(directory: Path, findings: list[dict[str, Any]]) -> None:
    content = read_text(directory / "nmap.txt")
    for line in content.splitlines():
        if re.match(r"^\d+/tcp\s+open\s+", line):
            add_finding(
                findings,
                title="Service reseau accessible",
                category="Attack Surface",
                severity="info",
                confidence="confirmed",
                tool="Nmap",
                evidence=line,
                description="Un service ouvert fait partie de la surface d'attaque a examiner.",
            )


def analyse_gobuster(directory: Path, findings: list[dict[str, Any]]) -> None:
    content = read_text(directory / "gobuster.txt")
    for line in content.splitlines():
        match = re.search(r"^(\S+)\s+\(Status:\s*(\d{3})\)", line.strip())
        if not match:
            continue
        path, _status = match.groups()
        severity = "low" if path.strip("/") in {"files", "src"} else "info"
        add_finding(
            findings,
            title=f"Ressource decouverte : /{path.lstrip('/')}",
            category="Content Discovery",
            severity=severity,
            confidence="confirmed",
            tool="Gobuster",
            evidence=line.strip(),
            description="La ressource existe ou redirige et doit etre verifiee manuellement.",
        )


def analyse_nikto(directory: Path, findings: list[dict[str, Any]]) -> None:
    content = read_text(directory / "nikto.txt") or read_text(directory / "nikto-console.txt")
    seen: set[str] = set()

    for line in content.splitlines():
        clean = line.strip().lstrip("+").strip()
        lowered = clean.lower()
        if not clean or clean in seen:
            continue

        if "security header missing" in lowered or "header is not set" in lowered:
            seen.add(clean)
            add_finding(
                findings,
                title="Header de securite manquant signale par Nikto",
                category="Security Misconfiguration",
                severity="low",
                confidence="confirmed",
                tool="Nikto",
                evidence=clean,
                description="Nikto a signale une faiblesse de configuration HTTP.",
            )
        elif "might be interesting" in lowered:
            seen.add(clean)
            add_finding(
                findings,
                title="Ressource potentiellement sensible",
                category="Content Discovery",
                severity="low",
                confidence="possible",
                tool="Nikto",
                evidence=clean,
                description="La ressource doit etre ouverte et analysee manuellement.",
            )


def safe_filename(url: str, index: int) -> str:
    path = urlparse(url).path
    name = Path(path).name or f"script-{index}.js"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return f"{index:02d}-{name}"


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    with urlopen(request, timeout=15, context=context) as response:
        data = response.read(MAX_JS_SIZE + 1)
        if len(data) > MAX_JS_SIZE:
            raise ValueError("fichier JavaScript trop volumineux")
        charset = response.headers.get_content_charset() or "utf-8"
        return data.decode(charset, errors="replace")


def discover_javascript(target: str, directory: Path) -> list[dict[str, str]]:
    log("Recherche des fichiers JavaScript dans la page")
    parser = ScriptParser()
    parser.feed(read_text(directory / "index.html"))

    target_origin = urlparse(target)
    js_directory = directory / "javascript"
    js_directory.mkdir(exist_ok=True)
    downloaded: list[dict[str, str]] = []

    for index, source in enumerate(dict.fromkeys(parser.scripts), start=1):
        if index > MAX_JS_FILES:
            log_warn(f"Limite de {MAX_JS_FILES} fichiers JavaScript atteinte.")
            break

        absolute_url = urljoin(f"{target}/", source)
        parsed = urlparse(absolute_url)
        if (parsed.scheme, parsed.hostname, parsed.port) != (
            target_origin.scheme,
            target_origin.hostname,
            target_origin.port,
        ):
            log_warn(f"Script externe ignore : {absolute_url}")
            continue

        try:
            content = fetch_text(absolute_url)
        except (HTTPError, URLError, TimeoutError, ValueError) as error:
            log_warn(f"Echec du telechargement de {absolute_url}: {error}")
            continue

        filename = safe_filename(absolute_url, index)
        (js_directory / filename).write_text(content, encoding="utf-8")
        downloaded.append({"url": absolute_url, "file": f"javascript/{filename}"})
        log_ok(f"JavaScript recupere : {absolute_url}")

    (directory / "javascript-files.json").write_text(
        json.dumps(downloaded, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log_ok(f"{len(downloaded)} fichier(s) JavaScript enregistre(s).")
    return downloaded


def normalize_route(value: str, target: str) -> str | None:
    value = value.strip()
    if not value or value.startswith(("data:", "javascript:", "mailto:")):
        return None
    if any(character in value for character in ("<", ">", "{", "}")):
        return None

    absolute = urljoin(f"{target}/", value)
    parsed = urlparse(absolute)
    target_parsed = urlparse(target)
    if parsed.hostname != target_parsed.hostname:
        return None

    route = parsed.path
    if parsed.query:
        route += f"?{parsed.query}"
    return route if route.startswith("/") else None


def analyse_javascript(
    target: str,
    directory: Path,
    javascript_files: list[dict[str, str]],
    findings: list[dict[str, Any]],
) -> list[dict[str, str]]:
    log("Extraction des routes et indices dans le JavaScript")
    routes: set[str] = set()

    for javascript_file in javascript_files:
        content = read_text(directory / javascript_file["file"])

        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = normalize_route(match.group(1), target)
                if route and any(marker in route.lower() for marker in INTERESTING_ROUTE_MARKERS):
                    routes.add(route)

        source_maps = re.findall(r"sourceMappingURL=([^\s*]+)", content)
        for source_map in source_maps:
            add_finding(
                findings,
                title="Source map JavaScript referencee",
                category="Information Disclosure",
                severity="low",
                confidence="possible",
                tool="JavaScript analysis",
                evidence=f"{javascript_file['url']} -> {source_map}",
                description="Une source map accessible peut faciliter la lecture du code source client.",
            )

        for title, pattern in SENSITIVE_JS_PATTERNS.items():
            if pattern.search(content):
                add_finding(
                    findings,
                    title=title,
                    category="Client-side Analysis",
                    severity="info",
                    confidence="possible",
                    tool="JavaScript analysis",
                    evidence=f"Motif trouve dans {javascript_file['url']}",
                    description="Il s'agit d'un indice a analyser, pas d'une vulnerabilite confirmee.",
                )

    endpoints = [{"method": "UNKNOWN", "path": route, "source": "javascript"} for route in sorted(routes)]
    (directory / "endpoints.json").write_text(
        json.dumps(endpoints, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log_ok(f"{len(endpoints)} route(s) interessante(s) extraite(s).")
    return endpoints


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    fingerprints: set[tuple[str, str]] = set()

    for finding in findings:
        fingerprint = (finding["title"], finding["evidence"].lower())
        if fingerprint not in fingerprints:
            fingerprints.add(fingerprint)
            unique.append(finding)

    return unique


def read_tool_status(directory: Path) -> list[tuple[str, str]]:
    statuses: list[tuple[str, str]] = []
    for line in read_text(directory / "tool-status.tsv").splitlines()[1:]:
        if "\t" in line:
            tool, status = line.split("\t", 1)
            statuses.append((tool, status))
    return statuses


def write_markdown(
    target: str,
    directory: Path,
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, str]],
) -> None:
    lines = [
        "# Rapport du scan MVP",
        "",
        f"**Cible :** `{target}`",
        "",
        "## Etat des outils",
        "",
        "| Outil | Etat |",
        "|---|---|",
    ]

    for tool, status in read_tool_status(directory):
        lines.append(f"| {tool} | {status} |")

    lines.extend(["", f"## Resultats ({len(findings)})", ""])

    if not findings:
        lines.append("Aucune faiblesse n'a ete extraite automatiquement.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding['title']}",
                    "",
                    f"- **Categorie :** {finding['category']}",
                    f"- **Gravite :** {finding['severity']}",
                    f"- **Confiance :** {finding['confidence']}",
                    f"- **Outil :** {finding['tool']}",
                    f"- **Preuve :** `{finding['evidence']}`",
                    f"- **Interpretation :** {finding['description']}",
                    "",
                ]
            )

    lines.extend(["## Routes extraites du JavaScript", ""])
    if endpoints:
        for endpoint in endpoints:
            lines.append(f"- `{endpoint['path']}`")
    else:
        lines.append("Aucune route interessante extraite automatiquement.")

    lines.extend(
        [
            "",
            "## Limites",
            "",
            "Cette version couvre la reconnaissance, les configurations HTTP, les cookies "
            "et l'analyse statique du JavaScript. Les routes et motifs detectes restent a verifier.",
            "",
        ]
    )

    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")


def severity_class(severity: str) -> str:
    return severity if severity in {"critical", "high", "medium", "low", "info"} else "info"


def write_html(
    target: str,
    directory: Path,
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, str]],
) -> None:
    status_rows = "".join(
        f"<tr><td>{html.escape(tool)}</td><td>{html.escape(status)}</td></tr>"
        for tool, status in read_tool_status(directory)
    )

    finding_cards = []
    for index, finding in enumerate(findings, start=1):
        severity = severity_class(finding["severity"])
        finding_cards.append(
            f"""
            <article class="finding">
              <div class="finding-title">
                <h3>{index}. {html.escape(finding['title'])}</h3>
                <span class="badge {severity}">{html.escape(finding['severity'])}</span>
              </div>
              <dl>
                <dt>Categorie</dt><dd>{html.escape(finding['category'])}</dd>
                <dt>Confiance</dt><dd>{html.escape(finding['confidence'])}</dd>
                <dt>Outil</dt><dd>{html.escape(finding['tool'])}</dd>
                <dt>Preuve</dt><dd><code>{html.escape(finding['evidence'])}</code></dd>
                <dt>Interpretation</dt><dd>{html.escape(finding['description'])}</dd>
              </dl>
            </article>
            """
        )

    if not finding_cards:
        finding_cards.append("<p>Aucune faiblesse extraite automatiquement.</p>")

    endpoint_items = "".join(
        f"<li><code>{html.escape(endpoint['path'])}</code></li>" for endpoint in endpoints
    ) or "<li>Aucune route interessante extraite automatiquement.</li>"

    document = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport de securite - {html.escape(target)}</title>
  <style>
    :root {{ color-scheme: light; font-family: Arial, sans-serif; }}
    body {{ margin: 0; background: #f3f5f7; color: #1d2733; }}
    main {{ max-width: 1050px; margin: 0 auto; padding: 32px 20px 60px; }}
    header, section, .finding {{ background: white; border: 1px solid #dfe5eb; border-radius: 10px; padding: 22px; margin-bottom: 18px; }}
    h1, h2, h3 {{ margin-top: 0; }}
    .target {{ overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e7ebef; }}
    .finding-title {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }}
    .badge {{ border-radius: 999px; padding: 5px 10px; font-size: 0.8rem; font-weight: bold; text-transform: uppercase; }}
    .critical, .high {{ background: #ffd7d7; }}
    .medium {{ background: #ffe8bd; }}
    .low {{ background: #fff4bd; }}
    .info {{ background: #dcecff; }}
    dl {{ display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; margin-bottom: 0; }}
    dt {{ font-weight: bold; }}
    dd {{ margin: 0; min-width: 0; overflow-wrap: anywhere; }}
    code {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
    li {{ margin: 8px 0; }}
    @media (max-width: 650px) {{ dl {{ grid-template-columns: 1fr; }} .finding-title {{ display: block; }} }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Rapport du scan MVP</h1>
      <p class="target"><strong>Cible :</strong> <code>{html.escape(target)}</code></p>
      <p><strong>Resultats :</strong> {len(findings)} constat(s), {len(endpoints)} route(s) extraite(s).</p>
    </header>
    <section>
      <h2>Etat des outils</h2>
      <table><thead><tr><th>Outil</th><th>Etat</th></tr></thead><tbody>{status_rows}</tbody></table>
    </section>
    <section>
      <h2>Constats</h2>
      {''.join(finding_cards)}
    </section>
    <section>
      <h2>Routes extraites du JavaScript</h2>
      <ul>{endpoint_items}</ul>
    </section>
    <section>
      <h2>Limites</h2>
      <p>Cette version realise de la reconnaissance, analyse les configurations HTTP, les cookies et le JavaScript. Les indices trouves doivent etre confirmes manuellement.</p>
    </section>
  </main>
</body>
</html>
"""
    (directory / "report.html").write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse les sorties du scanner MVP.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []

    analyse_headers(args.input, findings)
    analyse_cookies(args.input, findings)
    analyse_options(args.input, findings)
    analyse_cors(args.input, findings)

    log("Lecture des resultats WhatWeb, Nmap, Gobuster et Nikto")
    analyse_nmap(args.input, findings)
    analyse_gobuster(args.input, findings)
    analyse_nikto(args.input, findings)
    log_ok("Sorties des outils analysees.")

    javascript_files = discover_javascript(args.target, args.input)
    endpoints = analyse_javascript(args.target, args.input, javascript_files, findings)
    findings = deduplicate(findings)

    payload = {
        "target": args.target,
        "finding_count": len(findings),
        "endpoint_count": len(endpoints),
        "findings": findings,
        "endpoints": endpoints,
    }

    log("Generation des rapports JSON, Markdown et HTML")
    (args.input / "report.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_markdown(args.target, args.input, findings, endpoints)
    write_html(args.target, args.input, findings, endpoints)
    log_ok("Rapports generes avec succes.")


if __name__ == "__main__":
    main()
