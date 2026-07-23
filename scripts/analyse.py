#!/usr/bin/env python3

from __future__ import annotations

import argparse
import html
import json
import re
import ssl
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener, urlopen

from discovery import discover_surface

MAX_JS_FILES = 30
MAX_JS_SIZE = 5_000_000
MAX_RESPONSE_SIZE = 1_000_000
MAX_ACTIVE_TARGETS = 20
REQUEST_TIMEOUT = 12
USER_AGENT = "WebSecurityScanner-MVP/0.4"

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

PARAMETER_PATTERNS = [
    re.compile(
        r"(?:searchParams|queryParams|params)\.(?:get|set|append|has)\(\s*[\"']([A-Za-z0-9_.-]{1,80})[\"']",
        re.I,
    ),
    re.compile(r"[?&]([A-Za-z0-9_.-]{1,80})="),
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

ERROR_PATTERNS = {
    "Erreur SQL potentielle": re.compile(
        r"(?:sql syntax|sqlite_error|sequelize|mysql|postgresql|ora-\d+|sqlstate)",
        re.I,
    ),
    "Trace technique exposee": re.compile(
        r"(?:traceback \(most recent call last\)|stack trace|at [A-Za-z0-9_$.]+\s*\([^\n]+:\d+:\d+\))",
        re.I,
    ),
}

REDIRECT_PARAMETER_NAMES = {
    "url",
    "uri",
    "redirect",
    "redirect_url",
    "redirecturl",
    "return",
    "return_url",
    "returnurl",
    "next",
    "continue",
    "callback",
    "destination",
    "to",
}

ACTIVE_MUTATIONS = {
    "empty": "",
    "long": "A" * 256,
    "special": "'\"<>",
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        tag = tag.lower()

        if tag == "script" and attributes.get("src"):
            self.scripts.append(attributes["src"] or "")
        elif tag in {"a", "link"} and attributes.get("href"):
            self.links.append(attributes["href"] or "")
        elif tag == "form":
            self._current_form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "GET").upper(),
                "parameters": [],
            }
        elif tag in {"input", "select", "textarea", "button"} and self._current_form is not None:
            name = attributes.get("name")
            if name:
                self._current_form["parameters"].append(
                    {
                        "name": name,
                        "type": attributes.get("type") or tag,
                        "value": attributes.get("value") or "",
                    }
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


@dataclass
class HeaderResponse:
    status_line: str
    headers: dict[str, list[str]]


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float
    error: str | None = None


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


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


def same_origin(url: str, target: str) -> bool:
    parsed = urlparse(url)
    target_parsed = urlparse(target)
    return (
        parsed.scheme,
        parsed.hostname,
        parsed.port or (443 if parsed.scheme == "https" else 80),
    ) == (
        target_parsed.scheme,
        target_parsed.hostname,
        target_parsed.port or (443 if target_parsed.scheme == "https" else 80),
    )


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
            # Les headers sont deja controles directement afin d'eviter les doublons Nikto.
            continue
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
    with urlopen(request, timeout=REQUEST_TIMEOUT, context=context) as response:
        data = response.read(MAX_JS_SIZE + 1)
        if len(data) > MAX_JS_SIZE:
            raise ValueError("fichier JavaScript trop volumineux")
        charset = response.headers.get_content_charset() or "utf-8"
        return data.decode(charset, errors="replace")


def parse_page(directory: Path) -> PageParser:
    parser = PageParser()
    parser.feed(read_text(directory / "index.html"))
    return parser


def discover_javascript(target: str, directory: Path, page: PageParser) -> list[dict[str, str]]:
    log("Recherche des fichiers JavaScript dans la page")
    target_origin = urlparse(target)
    js_directory = directory / "javascript"
    js_directory.mkdir(exist_ok=True)
    downloaded: list[dict[str, str]] = []

    for index, source in enumerate(dict.fromkeys(page.scripts), start=1):
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
    if not same_origin(absolute, target):
        return None

    parsed = urlparse(absolute)
    route = parsed.path
    if parsed.query:
        route += f"?{parsed.query}"
    return route if route.startswith("/") else None


def endpoint_from_route(route: str, source: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    parsed = urlparse(route)
    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    endpoint = {
        "method": "GET" if query_pairs else "UNKNOWN",
        "path": parsed.path,
        "source": source,
    }
    parameters = [
        {
            "method": "GET",
            "path": parsed.path,
            "name": name,
            "location": "query",
            "source": source,
            "default_value": value,
            "active_testable": True,
        }
        for name, value in query_pairs
    ]
    return endpoint, parameters


def analyse_javascript(
    target: str,
    directory: Path,
    javascript_files: list[dict[str, str]],
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    log("Extraction des routes et parametres dans le JavaScript")
    routes: set[str] = set()
    unbound_parameters: set[str] = set()

    for javascript_file in javascript_files:
        content = read_text(directory / javascript_file["file"])

        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(content):
                route = normalize_route(match.group(1), target)
                if route and (
                    any(marker in route.lower() for marker in INTERESTING_ROUTE_MARKERS)
                    or "?" in route
                ):
                    routes.add(route)

        for pattern in PARAMETER_PATTERNS:
            for match in pattern.finditer(content):
                unbound_parameters.add(match.group(1))

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

    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    for route in sorted(routes):
        endpoint, route_parameters = endpoint_from_route(route, "javascript")
        endpoints.append(endpoint)
        parameters.extend(route_parameters)

    log_ok(f"{len(endpoints)} route(s) et {len(parameters)} parametre(s) lies extraits du JavaScript.")
    return endpoints, parameters, sorted(unbound_parameters)


def discover_html_parameters(
    target: str,
    page: PageParser,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    log("Extraction des parametres depuis les liens et formulaires HTML")
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []

    candidate_urls = [target]
    candidate_urls.extend(urljoin(f"{target}/", link) for link in page.links)

    for candidate in candidate_urls:
        if not same_origin(candidate, target):
            continue
        parsed = urlparse(candidate)
        pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if not pairs:
            continue
        endpoints.append({"method": "GET", "path": parsed.path or "/", "source": "html-link"})
        for name, value in pairs:
            parameters.append(
                {
                    "method": "GET",
                    "path": parsed.path or "/",
                    "name": name,
                    "location": "query",
                    "source": "html-link",
                    "default_value": value,
                    "active_testable": True,
                }
            )

    for form in page.forms:
        action_url = urljoin(f"{target}/", form["action"] or urlparse(target).path or "/")
        if not same_origin(action_url, target):
            continue
        parsed = urlparse(action_url)
        method = form["method"]
        endpoints.append({"method": method, "path": parsed.path or "/", "source": "html-form"})
        for parameter in form["parameters"]:
            parameters.append(
                {
                    "method": method,
                    "path": parsed.path or "/",
                    "name": parameter["name"],
                    "location": "query" if method == "GET" else "body",
                    "source": "html-form",
                    "default_value": parameter["value"],
                    "input_type": parameter["type"],
                    "active_testable": method == "GET",
                }
            )

    log_ok(f"{len(page.forms)} formulaire(s) HTML et {len(parameters)} parametre(s) trouves.")
    return endpoints, parameters


def deduplicate_records(records: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for record in records:
        fingerprint = tuple(record.get(key) for key in keys)
        if fingerprint not in seen:
            seen.add(fingerprint)
            unique.append(record)
    return unique


def request_get(url: str) -> HttpResult:
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    context = ssl._create_unverified_context() if url.startswith("https://") else None
    handlers: list[Any] = [NoRedirectHandler()]
    if context is not None:
        handlers.append(HTTPSHandler(context=context))
    opener = build_opener(*handlers)
    started = time.monotonic()

    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT)
        body_bytes = response.read(MAX_RESPONSE_SIZE + 1)
        if len(body_bytes) > MAX_RESPONSE_SIZE:
            body_bytes = body_bytes[:MAX_RESPONSE_SIZE]
        charset = response.headers.get_content_charset() or "utf-8"
        return HttpResult(
            url=url,
            status=response.getcode(),
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body_bytes.decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 3),
        )
    except HTTPError as error:
        body_bytes = error.read(MAX_RESPONSE_SIZE + 1)
        charset = error.headers.get_content_charset() or "utf-8"
        return HttpResult(
            url=url,
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=body_bytes[:MAX_RESPONSE_SIZE].decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 3),
        )
    except (URLError, TimeoutError, OSError) as error:
        return HttpResult(
            url=url,
            status=0,
            headers={},
            body="",
            elapsed=round(time.monotonic() - started, 3),
            error=str(error),
        )


def build_test_url(target: str, parameter: dict[str, Any], value: str) -> str:
    base = urljoin(f"{target}/", parameter["path"].lstrip("/"))
    parsed = urlparse(base)
    query = [(parameter["name"], value)]
    return urlunparse(parsed._replace(query=urlencode(query)))


def body_signature(body: str) -> str:
    normalized = re.sub(r"\s+", " ", body).strip()
    return normalized[:180]


def run_active_tests(
    target: str,
    parameters: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    testable = [parameter for parameter in parameters if parameter.get("active_testable")]
    testable = testable[:MAX_ACTIVE_TARGETS]
    results: list[dict[str, Any]] = []

    log(f"Preparation des tests actifs sur {len(testable)} parametre(s) GET")
    if not testable:
        log_warn("Aucun parametre GET testable n'a ete decouvert.")
        return results

    for index, parameter in enumerate(testable, start=1):
        label = f"{parameter['path']}?{parameter['name']}"
        log(f"Test actif {index}/{len(testable)} : {label}")
        baseline_value = parameter.get("default_value") or "scanner"
        baseline_url = build_test_url(target, parameter, baseline_value)
        baseline = request_get(baseline_url)

        parameter_result = {
            "method": "GET",
            "path": parameter["path"],
            "parameter": parameter["name"],
            "baseline": {
                "url": baseline.url,
                "status": baseline.status,
                "length": len(baseline.body),
                "elapsed": baseline.elapsed,
                "error": baseline.error,
            },
            "mutations": [],
        }

        if baseline.error:
            log_warn(f"Baseline inaccessible pour {label}: {baseline.error}")
            results.append(parameter_result)
            continue

        mutations = dict(ACTIVE_MUTATIONS)
        reflection_marker = f"WSS_REFLECT_{index:03d}"
        mutations["reflection"] = reflection_marker
        if parameter["name"].lower() in REDIRECT_PARAMETER_NAMES:
            mutations["external_redirect"] = "https://scanner.invalid/"

        for mutation_name, mutation_value in mutations.items():
            test_url = build_test_url(target, parameter, mutation_value)
            response = request_get(test_url)
            mutation_result = {
                "name": mutation_name,
                "url": test_url,
                "status": response.status,
                "length": len(response.body),
                "elapsed": response.elapsed,
                "error": response.error,
                "status_changed": response.status != baseline.status,
                "length_delta": len(response.body) - len(baseline.body),
                "body_preview": body_signature(response.body),
            }
            parameter_result["mutations"].append(mutation_result)

            if response.error:
                continue

            if response.status >= 500 and baseline.status < 500:
                add_finding(
                    findings,
                    title="Erreur serveur provoquee par une entree modifiee",
                    category="Improper Input Validation",
                    severity="medium",
                    confidence="probable",
                    tool="Active parameter tests",
                    evidence=f"GET {parameter['path']} ; parametre {parameter['name']} ; mutation {mutation_name} ; HTTP {response.status}",
                    description="Une valeur inhabituelle provoque une erreur serveur alors que la requete de reference ne le fait pas.",
                )

            for title, pattern in ERROR_PATTERNS.items():
                if pattern.search(response.body) and not pattern.search(baseline.body):
                    add_finding(
                        findings,
                        title=title,
                        category="Injection" if "SQL" in title else "Information Disclosure",
                        severity="medium",
                        confidence="probable",
                        tool="Active parameter tests",
                        evidence=f"GET {parameter['path']} ; parametre {parameter['name']} ; mutation {mutation_name}",
                        description="La reponse modifiee contient un motif d'erreur technique absent de la reponse de reference.",
                    )

            if mutation_name == "reflection" and reflection_marker in response.body:
                add_finding(
                    findings,
                    title="Entree utilisateur refletee dans la reponse",
                    category="XSS / Input Handling",
                    severity="low",
                    confidence="possible",
                    tool="Active parameter tests",
                    evidence=f"Le marqueur {reflection_marker} est retourne par {parameter['path']} via {parameter['name']}.",
                    description="La reflexion seule ne confirme pas une XSS. Le contexte HTML et l'encodage doivent etre verifies.",
                )

            if mutation_name == "external_redirect" and response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location", "")
                if location and urlparse(urljoin(test_url, location)).hostname == "scanner.invalid":
                    add_finding(
                        findings,
                        title="Redirection externe potentiellement non validee",
                        category="Unvalidated Redirects",
                        severity="medium",
                        confidence="probable",
                        tool="Active parameter tests",
                        evidence=f"{parameter['name']} provoque HTTP {response.status} vers {location}",
                        description="Le parametre semble permettre une redirection vers un domaine externe.",
                    )

            if response.elapsed > baseline.elapsed + 3 and response.elapsed > 4:
                add_finding(
                    findings,
                    title="Temps de reponse anormal apres mutation",
                    category="Improper Input Validation",
                    severity="info",
                    confidence="possible",
                    tool="Active parameter tests",
                    evidence=f"{label} ; baseline {baseline.elapsed}s ; mutation {mutation_name} {response.elapsed}s",
                    description="Cette variation peut signaler un traitement particulier, mais doit etre reproduite manuellement.",
                )

        results.append(parameter_result)
        log_ok(f"Tests termines pour {label}")

    log_ok(f"Tests actifs termines sur {len(results)} parametre(s).")
    return results


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return deduplicate_records(findings, ("title", "evidence"))


def read_tool_status(directory: Path) -> list[tuple[str, str]]:
    statuses: list[tuple[str, str]] = []
    for line in read_text(directory / "tool-status.tsv").splitlines()[1:]:
        if "\t" in line:
            tool, status = line.split("\t", 1)
            statuses.append((tool, status))
    return statuses


def write_markdown(
    target: str,
    mode: str,
    directory: Path,
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
    sensitive_routes: list[dict[str, Any]],
    profiles: list[str],
    active_results: list[dict[str, Any]],
) -> None:
    lines = [
        "# Rapport du scan MVP 0.4",
        "",
        f"**Cible :** `{target}`",
        f"**Mode :** `{mode}`",
        f"**Profil applique :** `{', '.join(profiles) if profiles else 'global uniquement'}`",
        "",
        "## Etat des outils",
        "",
        "| Outil | Etat |",
        "|---|---|",
    ]

    for tool, status in read_tool_status(directory):
        lines.append(f"| {tool} | {status} |")

    lines.extend(["", f"## Constats ({len(findings)})", ""])
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

    lines.extend(["## Routes sensibles", ""])
    if sensitive_routes:
        lines.extend(["| Route | Type | Categorie | Sensibilite | HTTP | Accessible | Source |", "|---|---|---|---|---|---|---|"])
        for item in sensitive_routes:
            status = item.get("status") if item.get("status") is not None else "-"
            accessible = "oui" if item.get("accessible") is True else "non" if item.get("accessible") is False else "non testee"
            lines.append(
                f"| `{item.get('path', '')}` | {item.get('kind', '')} | {item.get('category', '')} | "
                f"{item.get('sensitivity', '')} | {status} | {accessible} | {item.get('source', '')} |"
            )
    else:
        lines.append("Aucune route sensible identifiee.")

    lines.extend(["", "## Endpoints decouverts", ""])
    if endpoints:
        lines.extend(["| Methode | Route | Type | Sensibilite | HTTP | Source |", "|---|---|---|---|---|---|"])
        for endpoint in endpoints:
            status = endpoint.get("status") if endpoint.get("status") is not None else "-"
            lines.append(
                f"| {endpoint.get('method', 'UNKNOWN')} | `{endpoint.get('path', '')}` | {endpoint.get('kind', '')} | "
                f"{endpoint.get('sensitivity', '')} | {status} | {endpoint.get('source', '')} |"
            )
    else:
        lines.append("Aucun endpoint extrait automatiquement.")

    lines.extend(["", "## Parametres decouverts", ""])
    if parameters:
        lines.extend(["| Methode | Route | Parametre | Emplacement | Source | Test actif |", "|---|---|---|---|---|---|"])
        for parameter in parameters:
            lines.append(
                f"| {parameter['method']} | `{parameter['path']}` | `{parameter['name']}` | "
                f"{parameter['location']} | {parameter['source']} | "
                f"{'oui' if parameter.get('active_testable') else 'non'} |"
            )
    else:
        lines.append("Aucun parametre associe a une route n'a ete decouvert.")

    lines.extend(["", "## Tests actifs", ""])
    if mode != "active":
        lines.append("Non executes : relancer avec `--active`.")
    elif active_results:
        lines.append(f"{len(active_results)} parametre(s) GET ont ete testes avec des mutations limitees.")
    else:
        lines.append("Aucun parametre GET testable n'a ete trouve.")

    lines.extend(
        [
            "",
            "## Limites",
            "",
            "La cartographie statique ne remplace pas un navigateur executant le JavaScript. Les routes authentifiees, "
            "les formulaires POST et les controles d'acces complexes restent a verifier manuellement ou avec un fichier HAR.",
            "",
        ]
    )
    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")


def severity_class(severity: str) -> str:
    return severity if severity in {"critical", "high", "medium", "low", "info"} else "info"


def write_html(
    target: str,
    mode: str,
    directory: Path,
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
    sensitive_routes: list[dict[str, Any]],
    profiles: list[str],
    active_results: list[dict[str, Any]],
) -> None:
    status_rows = "".join(
        f"<tr><td>{html.escape(tool)}</td><td>{html.escape(status)}</td></tr>"
        for tool, status in read_tool_status(directory)
    ) or '<tr><td colspan="2">Aucun statut disponible</td></tr>'

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

    sensitive_rows = "".join(
        "<tr>"
        f"<td><code>{html.escape(str(item.get('path', '')))}</code></td>"
        f"<td>{html.escape(str(item.get('kind', '')))}</td>"
        f"<td>{html.escape(str(item.get('category', '')))}</td>"
        f"<td>{html.escape(str(item.get('sensitivity', '')))}</td>"
        f"<td>{html.escape(str(item.get('status') if item.get('status') is not None else '-'))}</td>"
        f"<td>{'oui' if item.get('accessible') is True else 'non' if item.get('accessible') is False else 'non testee'}</td>"
        f"<td>{html.escape(str(item.get('source', '')))}</td>"
        "</tr>"
        for item in sensitive_routes
    ) or '<tr><td colspan="7">Aucune route sensible identifiee.</td></tr>'

    endpoint_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(endpoint.get('method', 'UNKNOWN')))}</td>"
        f"<td><code>{html.escape(str(endpoint.get('path', '')))}</code></td>"
        f"<td>{html.escape(str(endpoint.get('kind', '')))}</td>"
        f"<td>{html.escape(str(endpoint.get('sensitivity', '')))}</td>"
        f"<td>{html.escape(str(endpoint.get('status') if endpoint.get('status') is not None else '-'))}</td>"
        f"<td>{html.escape(str(endpoint.get('source', '')))}</td>"
        "</tr>"
        for endpoint in endpoints
    ) or '<tr><td colspan="6">Aucun endpoint decouvert.</td></tr>'

    parameter_rows = "".join(
        f"<tr><td>{html.escape(parameter['method'])}</td><td><code>{html.escape(parameter['path'])}</code></td>"
        f"<td><code>{html.escape(parameter['name'])}</code></td><td>{html.escape(parameter['location'])}</td>"
        f"<td>{html.escape(parameter['source'])}</td><td>{'oui' if parameter.get('active_testable') else 'non'}</td></tr>"
        for parameter in parameters
    ) or '<tr><td colspan="6">Aucun parametre associe a une route.</td></tr>'

    active_summary = (
        f"{len(active_results)} parametre(s) GET testes. Details dans <code>active-tests.json</code>."
        if mode == "active"
        else "Tests non executes. Relancer avec <code>--active</code>."
    )
    profile_text = ", ".join(profiles) if profiles else "global uniquement"

    document = f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Rapport de securite - {html.escape(target)}</title>
  <style>
    :root {{ color-scheme: light; font-family: Arial, sans-serif; }}
    body {{ margin: 0; background: #f3f5f7; color: #1d2733; }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 60px; }}
    header, section, .finding {{ background: white; border: 1px solid #dfe5eb; border-radius: 10px; padding: 22px; margin-bottom: 18px; }}
    h1, h2, h3 {{ margin-top: 0; }}
    .target {{ overflow-wrap: anywhere; }}
    table {{ width: 100%; border-collapse: collapse; display: block; overflow-x: auto; }}
    th, td {{ text-align: left; padding: 10px; border-bottom: 1px solid #e7ebef; vertical-align: top; }}
    .finding-title {{ display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }}
    .badge {{ border-radius: 999px; padding: 5px 10px; font-size: .8rem; font-weight: bold; text-transform: uppercase; }}
    .critical, .high {{ background: #ffd7d7; }} .medium {{ background: #ffe8bd; }}
    .low {{ background: #fff4bd; }} .info {{ background: #dcecff; }}
    dl {{ display: grid; grid-template-columns: 130px 1fr; gap: 8px 14px; margin-bottom: 0; }}
    dt {{ font-weight: bold; }} dd {{ margin: 0; min-width: 0; overflow-wrap: anywhere; }}
    code {{ white-space: pre-wrap; overflow-wrap: anywhere; }}
    @media (max-width: 650px) {{ dl {{ grid-template-columns: 1fr; }} .finding-title {{ display: block; }} }}
  </style>
</head>
<body><main>
  <header>
    <h1>Rapport du scan MVP 0.4</h1>
    <p class="target"><strong>Cible :</strong> <code>{html.escape(target)}</code></p>
    <p><strong>Mode :</strong> {html.escape(mode)} — <strong>Profil :</strong> {html.escape(profile_text)}</p>
    <p><strong>Resume :</strong> {len(findings)} constat(s), {len(endpoints)} endpoint(s), {len(parameters)} parametre(s), {len(sensitive_routes)} route(s) sensible(s).</p>
  </header>
  <section><h2>Etat des outils</h2><table><thead><tr><th>Outil</th><th>Etat</th></tr></thead><tbody>{status_rows}</tbody></table></section>
  <section><h2>Constats</h2>{''.join(finding_cards)}</section>
  <section><h2>Routes sensibles</h2><table><thead><tr><th>Route</th><th>Type</th><th>Categorie</th><th>Sensibilite</th><th>HTTP</th><th>Accessible</th><th>Source</th></tr></thead><tbody>{sensitive_rows}</tbody></table></section>
  <section><h2>Endpoints decouverts</h2><table><thead><tr><th>Methode</th><th>Route</th><th>Type</th><th>Sensibilite</th><th>HTTP</th><th>Source</th></tr></thead><tbody>{endpoint_rows}</tbody></table></section>
  <section><h2>Parametres decouverts</h2><table><thead><tr><th>Methode</th><th>Route</th><th>Parametre</th><th>Emplacement</th><th>Source</th><th>Test actif</th></tr></thead><tbody>{parameter_rows}</tbody></table></section>
  <section><h2>Tests actifs</h2><p>{active_summary}</p></section>
  <section><h2>Limites</h2><p>La cartographie statique ne remplace pas un navigateur executant le JavaScript. Les routes authentifiees, formulaires POST et controles d'acces complexes restent a verifier manuellement ou via un fichier HAR.</p></section>
</main></body></html>
"""
    (directory / "report.html").write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse les sorties du scanner MVP.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--mode", choices=["passive", "active"], default="passive")
    parser.add_argument("--profile", default="auto", help="auto, none ou nom d'un profil dans config/profiles")
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

    config_dir = Path(__file__).resolve().parent.parent / "config"
    endpoints, parameters, sensitive_routes, profiles = discover_surface(
        target=args.target,
        directory=args.input,
        config_dir=config_dir,
        profile=args.profile,
        findings=findings,
        add_finding=add_finding,
    )

    (args.input / "endpoints.json").write_text(
        json.dumps(endpoints, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (args.input / "parameters.json").write_text(
        json.dumps({"parameters": parameters}, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    active_results: list[dict[str, Any]] = []
    if args.mode == "active":
        active_results = run_active_tests(args.target, parameters, findings)
    else:
        log("Mode passif : tests de mutation ignores.")

    (args.input / "active-tests.json").write_text(
        json.dumps(active_results, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    findings = deduplicate(findings)
    payload = {
        "version": "0.4.0",
        "target": args.target,
        "mode": args.mode,
        "profiles": profiles,
        "finding_count": len(findings),
        "endpoint_count": len(endpoints),
        "parameter_count": len(parameters),
        "sensitive_route_count": len(sensitive_routes),
        "active_test_count": len(active_results),
        "findings": findings,
        "sensitive_routes": sensitive_routes,
        "endpoints": endpoints,
        "parameters": parameters,
        "active_tests": active_results,
    }

    log("Generation des rapports JSON, Markdown et HTML")
    (args.input / "report.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    write_markdown(
        args.target, args.mode, args.input, findings, endpoints, parameters,
        sensitive_routes, profiles, active_results
    )
    write_html(
        args.target, args.mode, args.input, findings, endpoints, parameters,
        sensitive_routes, profiles, active_results
    )
    log_ok("Rapports generes avec succes.")


if __name__ == "__main__":
    main()
