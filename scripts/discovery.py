#!/usr/bin/env python3

from __future__ import annotations

import difflib
import hashlib
import html as html_lib
import json
import re
import ssl
import time
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import (
    parse_qsl,
    quote,
    urljoin,
    urlparse,
    urlsplit,
    urlunsplit,
)
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

USER_AGENT = "WebSecurityScanner-MVP/0.4"
REQUEST_TIMEOUT = 10
MAX_BODY_SIZE = 750_000
MAX_JS_SIZE = 6_000_000
MAX_JS_FILES = 40
MAX_CRAWL_PAGES = 25
MAX_CRAWL_DEPTH = 2
MAX_PROBED_ROUTES = 80

STATIC_EXTENSIONS = {
    ".7z", ".avi", ".bmp", ".css", ".doc", ".docx", ".eot", ".gif", ".gz",
    ".ico", ".jpeg", ".jpg", ".map", ".mp3", ".mp4", ".pdf", ".png", ".rar",
    ".svg", ".tar", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls",
    ".xlsx", ".zip",
}

SENSITIVE_MARKERS: list[tuple[tuple[str, ...], str, str]] = [
    ((".env", ".git", "config", "configuration", "source", "src", "sourcemap"), "Configuration / source", "high"),
    (("admin", "administration", "manage", "management", "console", "dashboard", "backoffice"), "Administration", "high"),
    (("metrics", "actuator", "debug", "trace", "profiler", "server-status", "health", "status"), "Monitoring / diagnostic", "high"),
    (("backup", "backups", "archive", "dump", "database", "db", "logs", "log", "access.log"), "Sauvegardes / journaux", "high"),
    (("ftp", "files", "file", "download", "downloads", "upload", "uploads", "quarantine", "export"), "Fichiers / transferts", "medium"),
    (("login", "auth", "oauth", "token", "jwt", "password", "reset", "forgot", "2fa", "mfa"), "Authentification", "medium"),
    (("redirect", "callback", "returnurl", "return_url", "next", "continue", "destination"), "Redirection", "medium"),
    (("basket", "cart", "order", "track", "payment", "wallet", "coupon", "invoice"), "Transaction / objet metier", "medium"),
    (("internal", "private", "secret", "hidden", "score-board", "scoreboard"), "Interne / cache", "medium"),
    (("swagger", "openapi", "api-docs", "graphql", "graphiql", "api", "rest"), "API / documentation", "medium"),
]


SENSITIVE_JS_PATTERNS = {
    "Stockage local utilise": re.compile(r"\blocalStorage\b"),
    "Stockage de session utilise": re.compile(r"\bsessionStorage\b"),
    "Jeton d'autorisation mentionne": re.compile(r"\b(?:Authorization|Bearer)\b", re.I),
    "Secret potentiel mentionne": re.compile(r"\b(?:api[_-]?key|client[_-]?secret|password|token)\b\s*[:=]", re.I),
}

STRING_LITERAL = r'(?:"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|`(?:\\.|[^`\\])*`)'

HTTP_CALL_PATTERNS = [
    re.compile(rf"\bfetch\s*\(\s*(?P<value>{STRING_LITERAL})", re.I | re.S),
    re.compile(
        rf"\b(?:axios|http|client|api|request|this\.http)\s*\.\s*"
        rf"(?P<method>get|post|put|patch|delete|head|options)\s*\(\s*(?P<value>{STRING_LITERAL})",
        re.I | re.S,
    ),
    re.compile(
        rf"\.open\s*\(\s*[\"\'](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"\']\s*,\s*"
        rf"(?P<value>{STRING_LITERAL})",
        re.I | re.S,
    ),
]

URL_CONTEXT_PATTERNS = [
    re.compile(rf"\b(?:url|uri|endpoint|baseURL|action|href)\s*[:=]\s*(?P<value>{STRING_LITERAL})", re.I | re.S),
    re.compile(rf"\b(?:navigateByUrl|routerLink)\s*\(\s*(?P<value>{STRING_LITERAL})", re.I | re.S),
]

ROUTE_CONFIG_PATTERNS = [
    re.compile(rf"\bpath\s*:\s*(?P<value>{STRING_LITERAL})", re.I | re.S),
    re.compile(rf"\bredirectTo\s*:\s*(?P<value>{STRING_LITERAL})", re.I | re.S),
]

QUOTED_STRING_PATTERN = re.compile(STRING_LITERAL, re.S)
SOURCE_MAP_PATTERN = re.compile(r"sourceMappingURL=([^\s*]+)")


@dataclass
class HttpResult:
    requested_url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float
    error: str | None = None


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


class SurfaceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.inline_scripts: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self.frames: list[str] = []
        self._form: dict[str, Any] | None = None
        self._inside_script = False
        self._script_parts: list[str] = []
        self.title = ""
        self._inside_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs}
        tag = tag.lower()

        if tag in {"a", "link"} and attributes.get("href"):
            self.links.append(attributes["href"] or "")
        elif tag == "script":
            if attributes.get("src"):
                self.scripts.append(attributes["src"] or "")
            else:
                self._inside_script = True
                self._script_parts = []
        elif tag in {"iframe", "frame"} and attributes.get("src"):
            self.frames.append(attributes["src"] or "")
        elif tag == "form":
            self._form = {
                "action": attributes.get("action") or "",
                "method": (attributes.get("method") or "GET").upper(),
                "parameters": [],
            }
        elif tag in {"input", "select", "textarea", "button"} and self._form is not None:
            name = attributes.get("name")
            if name:
                self._form["parameters"].append(
                    {
                        "name": name,
                        "type": attributes.get("type") or tag,
                        "value": attributes.get("value") or "",
                    }
                )
        elif tag == "title":
            self._inside_title = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "script" and self._inside_script:
            content = "".join(self._script_parts).strip()
            if content:
                self.inline_scripts.append(content)
            self._inside_script = False
            self._script_parts = []
        elif tag == "title":
            self._inside_title = False

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self._script_parts.append(data)
        elif self._inside_title:
            self.title += data.strip()


def log(message: str) -> None:
    print(f"      -> {message}")


def log_ok(message: str) -> None:
    print(f"      [OK] {message}")


def log_warn(message: str) -> None:
    print(f"      [!] {message}")


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


def build_opener_for(url: str) -> Any:
    handlers: list[Any] = [NoRedirectHandler()]
    if url.startswith("https://"):
        handlers.append(HTTPSHandler(context=ssl._create_unverified_context()))
    return build_opener(*handlers)

def encode_url_for_request(url: str) -> str:
    """
    Convertit une URL Unicode en URL HTTP correctement encodée.

    Exemple :
    /préférences -> /pr%C3%A9f%C3%A9rences
    ?q=café      -> ?q=caf%C3%A9
    """
    parts = urlsplit(url)

    encoded_path = quote(
        parts.path,
        safe="/%:@!$&'()*+,;=-._~",
    )

    encoded_query = quote(
        parts.query,
        safe="=&%/:?@!$'()*+,;[]-._~",
    )

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            encoded_path,
            encoded_query,
            "",  # Le fragment #... n'est pas envoyé au serveur.
        )
    )

def request_url(url: str, *, max_size: int = MAX_BODY_SIZE) -> HttpResult:
    started = time.monotonic()

    try:
        encoded_url = encode_url_for_request(url)

        request = Request(
            encoded_url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
            },
        )

        opener = build_opener_for(encoded_url)
        response = opener.open(request, timeout=REQUEST_TIMEOUT)
        body_bytes = response.read(max_size + 1)[:max_size]
        charset = response.headers.get_content_charset() or "utf-8"
        return HttpResult(
            requested_url=url,
            final_url=response.geturl(),
            status=response.getcode(),
            headers={key.lower(): value for key, value in response.headers.items()},
            body=body_bytes.decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 3),
        )
    except HTTPError as error:
        body_bytes = error.read(max_size + 1)[:max_size]
        charset = error.headers.get_content_charset() or "utf-8"
        return HttpResult(
            requested_url=url,
            final_url=url,
            status=error.code,
            headers={key.lower(): value for key, value in error.headers.items()},
            body=body_bytes.decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 3),
        )
    except (
    URLError,
    TimeoutError,
    OSError,
    UnicodeError,
    ValueError,
) as error:
        return HttpResult(
            requested_url=url,
            final_url=url,
            status=0,
            headers={},
            body="",
            elapsed=round(time.monotonic() - started, 3),
            error=str(error),
        )


def title_from_html(content: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", html_lib.unescape(match.group(1))).strip()[:160]


def response_signature(result: HttpResult) -> dict[str, Any]:
    normalized = re.sub(r"\s+", " ", result.body[:80_000]).strip()
    return {
        "status": result.status,
        "length": len(result.body),
        "content_type": result.headers.get("content-type", "").split(";", 1)[0].lower(),
        "title": title_from_html(result.body),
        "hash": hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest(),
        "sample": normalized[:20_000],
    }


def equivalent_to_baseline(result: HttpResult, baseline: HttpResult) -> bool:
    if result.status != baseline.status:
        return False
    left = response_signature(result)
    right = response_signature(baseline)
    if left["hash"] == right["hash"]:
        return True
    max_len = max(left["length"], right["length"], 1)
    if abs(left["length"] - right["length"]) / max_len > 0.04:
        return False
    if left["content_type"] != right["content_type"]:
        return False
    if left["title"] and right["title"] and left["title"] != right["title"]:
        return False
    ratio = difflib.SequenceMatcher(None, left["sample"], right["sample"]).ratio()
    return ratio >= 0.96


def decode_js_literal(token: str) -> str:
    token = token.strip()
    if len(token) < 2 or token[0] not in {'"', "'", "`"}:
        return token
    value = token[1:-1]
    value = re.sub(r"\$\{[^}]+\}", "{param}", value)
    replacements = {
        r"\/": "/",
        r"\n": " ",
        r"\r": " ",
        r"\t": " ",
        r"\u002f": "/",
        r"\u002F": "/",
        r"\x2f": "/",
        r"\x2F": "/",
    }
    for source, replacement in replacements.items():
        value = value.replace(source, replacement)
    value = value.replace(r"\'", "'").replace(r'\"', '"').replace(r"\\", "\\")
    return value.strip()


def augment_dynamic_suffix(content: str, end: int, value: str) -> str:
    tail = content[end : end + 100]
    if re.match(r"\s*\+\s*[A-Za-z_$][A-Za-z0-9_$.[\]]*", tail):
        if not value.endswith(("/", "=", "-", "_")):
            value += "/"
        value += "{param}"
    return value


def clean_candidate(value: str) -> str:
    value = html_lib.unescape(value.strip())
    value = value.replace("\\/", "/")
    value = re.sub(r"\s+", "", value)
    value = value.strip('"\'`')
    if len(value) > 500:
        return ""
    if any(character in value for character in ("<", ">", "\n", "\r")):
        return ""
    return value


def classify_route(path: str) -> tuple[str, str]:
    lowered = path.lower()
    for markers, category, sensitivity in SENSITIVE_MARKERS:
        if any(marker in lowered for marker in markers):
            return category, sensitivity
    return "Application", "low"


def looks_like_route(value: str, *, route_context: bool = False) -> bool:
    value = clean_candidate(value)
    if not value or len(value) < 2:
        return False
    lowered = value.lower()
    if lowered.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return False
    if value.startswith(("/", "./", "../", "#/", "http://", "https://")):
        return True
    if route_context and re.fullmatch(r"[A-Za-z0-9_.~!$&'()*+,;=:@%{}-]+(?:/[A-Za-z0-9_.~!$&'()*+,;=:@%{}-]+)*", value):
        return True
    category, _ = classify_route(value)
    return category != "Application" and "." not in value.split("/", 1)[0]


def normalize_route(value: str, target: str, *, route_context: bool = False) -> dict[str, Any] | None:
    value = clean_candidate(value)
    if not looks_like_route(value, route_context=route_context):
        return None

    value = re.sub(r":([A-Za-z_][A-Za-z0-9_]*)", r"{\1}", value)
    value = value.replace("${param}", "{param}")

    if value.startswith("http://") or value.startswith("https://"):
        if not same_origin(value, target):
            return None
        parsed = urlparse(value)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        if parsed.fragment:
            path += f"#{parsed.fragment}"
        kind = "client" if parsed.fragment.startswith("/") else "server"
    elif value.startswith("/#/"):
        path = value
        kind = "client"
    elif value.startswith("#/"):
        path = f"/{value}"
        kind = "client"
    elif route_context and not value.startswith(("/", "./", "../")):
        path = f"/#/{value.lstrip('/')}"
        kind = "client"
    else:
        absolute = urljoin(f"{target}/", value)
        if not same_origin(absolute, target):
            return None
        parsed = urlparse(absolute)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        kind = "server"

    path = re.sub(r"//+", "/", path.replace(":/", "://"))
    category, sensitivity = classify_route(path)
    return {
        "path": path,
        "kind": kind,
        "category": category,
        "sensitivity": sensitivity,
    }


def split_route_query(path: str) -> tuple[str, list[tuple[str, str]]]:
    if path.startswith("/#/"):
        virtual = path[2:]
        parsed = urlparse(virtual)
        return f"/#/{parsed.path.lstrip('/')}", parse_qsl(parsed.query, keep_blank_values=True)
    parsed = urlparse(path)
    return parsed.path or "/", parse_qsl(parsed.query, keep_blank_values=True)


def parameters_from_route(route: dict[str, Any], method: str, source: str) -> list[dict[str, Any]]:
    path_without_query, query_pairs = split_route_query(route["path"])
    parameters: list[dict[str, Any]] = []
    for name, value in query_pairs:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,79}", name):
            continue
        parameters.append(
            {
                "method": method if method != "UNKNOWN" else "GET",
                "path": path_without_query,
                "name": name,
                "location": "query",
                "source": source,
                "default_value": value,
                "active_testable": route["kind"] == "server" and method in {"GET", "UNKNOWN"},
            }
        )

    for name in re.findall(r"\{([A-Za-z_][A-Za-z0-9_]*)\}", path_without_query):
        parameters.append(
            {
                "method": method,
                "path": path_without_query,
                "name": name,
                "location": "path",
                "source": source,
                "default_value": "",
                "active_testable": False,
            }
        )
    if "{param}" in path_without_query and not any(item["location"] == "path" for item in parameters):
        parameters.append(
            {
                "method": method,
                "path": path_without_query,
                "name": "path_param",
                "location": "path",
                "source": source,
                "default_value": "",
                "active_testable": False,
            }
        )
    return parameters


def endpoint_record(route: dict[str, Any], method: str, source: str, **extra: Any) -> dict[str, Any]:
    record = {
        "method": method,
        "path": route["path"],
        "source": source,
        "kind": route["kind"],
        "category": route["category"],
        "sensitivity": route["sensitivity"],
    }
    record.update(extra)
    return record


def parse_html(content: str) -> SurfaceParser:
    parser = SurfaceParser()
    try:
        parser.feed(content)
    except Exception:
        pass
    return parser


def should_crawl(url: str, target: str) -> bool:
    if not same_origin(url, target):
        return False
    parsed = urlparse(url)
    if parsed.fragment:
        url = url.split("#", 1)[0]
        parsed = urlparse(url)
    suffix = Path(parsed.path).suffix.lower()
    return suffix not in STATIC_EXTENSIONS


def add_html_surface(
    *,
    target: str,
    page_url: str,
    parser: SurfaceParser,
    source: str,
    endpoints: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
    script_urls: set[str],
    inline_scripts: list[tuple[str, str]],
) -> list[str]:
    new_links: list[str] = []

    for link in parser.links + parser.frames:
        absolute = urljoin(page_url, link)
        if not same_origin(absolute, target):
            continue
        fragment = urlparse(absolute).fragment
        raw_route = f"/#/{fragment.lstrip('/')}" if fragment.startswith("/") else absolute
        route = normalize_route(raw_route, target, route_context=fragment.startswith("/"))
        if route:
            method = "GET"
            endpoints.append(endpoint_record(route, method, source))
            parameters.extend(parameters_from_route(route, method, source))
        if should_crawl(absolute.split("#", 1)[0], target):
            new_links.append(absolute.split("#", 1)[0])

    for form in parser.forms:
        action_url = urljoin(page_url, form["action"] or page_url)
        if not same_origin(action_url, target):
            continue
        route = normalize_route(action_url, target)
        if not route:
            continue
        method = form["method"] if form["method"] in {"GET", "POST", "PUT", "PATCH", "DELETE"} else "UNKNOWN"
        endpoints.append(endpoint_record(route, method, f"{source}-form"))
        for item in form["parameters"]:
            parameters.append(
                {
                    "method": method,
                    "path": split_route_query(route["path"])[0],
                    "name": item["name"],
                    "location": "query" if method == "GET" else "body",
                    "source": f"{source}-form",
                    "default_value": item["value"],
                    "input_type": item["type"],
                    "active_testable": method == "GET" and route["kind"] == "server",
                }
            )

    for script in parser.scripts:
        absolute = urljoin(page_url, script)
        if same_origin(absolute, target):
            script_urls.add(absolute)
    for index, inline in enumerate(parser.inline_scripts, start=1):
        inline_scripts.append((f"{page_url}#inline-{index}", inline))

    return new_links


def crawl_site(target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str], list[tuple[str, str]], list[dict[str, Any]], str]:
    log("Exploration HTML limitee au meme site")
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    script_urls: set[str] = set()
    inline_scripts: list[tuple[str, str]] = []
    pages: list[dict[str, Any]] = []
    queue: deque[tuple[str, int]] = deque([(target, 0)])
    visited: set[str] = set()
    root_text = ""

    while queue and len(visited) < MAX_CRAWL_PAGES:
        url, depth = queue.popleft()
        canonical = url.split("#", 1)[0]
        if canonical in visited or depth > MAX_CRAWL_DEPTH or not should_crawl(canonical, target):
            continue
        visited.add(canonical)
        result = request_url(canonical)
        content_type = result.headers.get("content-type", "").lower()
        pages.append(
            {
                "url": canonical,
                "status": result.status,
                "content_type": content_type,
                "title": title_from_html(result.body),
                "length": len(result.body),
                "depth": depth,
                "error": result.error,
            }
        )
        if canonical == target:
            root_text = result.body
        if result.status == 0 or "html" not in content_type and "<html" not in result.body[:500].lower():
            continue
        parser = parse_html(result.body)
        links = add_html_surface(
            target=target,
            page_url=canonical,
            parser=parser,
            source="html-crawl",
            endpoints=endpoints,
            parameters=parameters,
            script_urls=script_urls,
            inline_scripts=inline_scripts,
        )
        for link in links:
            if link not in visited:
                queue.append((link, depth + 1))

    log_ok(f"{len(pages)} page(s) HTML examinee(s), {len(script_urls)} script(s) reference(s).")
    return endpoints, parameters, script_urls, inline_scripts, pages, root_text


def safe_filename(url: str, index: int) -> str:
    name = Path(urlparse(url).path).name or f"script-{index}.js"
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    return f"{index:02d}-{name}"


def download_javascript(target: str, directory: Path, script_urls: Iterable[str]) -> list[dict[str, str]]:
    log("Telechargement des fichiers JavaScript du meme site")
    js_directory = directory / "javascript"
    js_directory.mkdir(exist_ok=True)
    downloaded: list[dict[str, str]] = []

    for index, url in enumerate(sorted(set(script_urls)), start=1):
        if index > MAX_JS_FILES:
            log_warn(f"Limite de {MAX_JS_FILES} fichiers JavaScript atteinte.")
            break
        if not same_origin(url, target):
            continue
        result = request_url(url, max_size=MAX_JS_SIZE)
        if result.status != 200 or not result.body:
            log_warn(f"JavaScript non recupere ({result.status}) : {url}")
            continue
        filename = safe_filename(url, index)
        relative = f"javascript/{filename}"
        (directory / relative).write_text(result.body, encoding="utf-8")
        downloaded.append({"url": url, "file": relative})
        log_ok(f"JavaScript recupere : {url}")

    (directory / "javascript-files.json").write_text(
        json.dumps(downloaded, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log_ok(f"{len(downloaded)} fichier(s) JavaScript enregistre(s).")
    return downloaded


def extract_routes_from_js(
    *,
    target: str,
    source_name: str,
    content: str,
    endpoints: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    add_finding: Callable[..., None],
) -> None:
    seen_candidates: set[tuple[str, str, str]] = set()

    def add_candidate(raw: str, method: str, source: str, route_context: bool, end: int | None = None) -> None:
        value = decode_js_literal(raw)
        if end is not None:
            value = augment_dynamic_suffix(content, end, value)
        route = normalize_route(value, target, route_context=route_context)
        if not route:
            return
        fingerprint = (method, route["path"], source)
        if fingerprint in seen_candidates:
            return
        seen_candidates.add(fingerprint)
        endpoints.append(endpoint_record(route, method, source))
        parameters.extend(parameters_from_route(route, method, source))

    for pattern in HTTP_CALL_PATTERNS:
        for match in pattern.finditer(content):
            method = (match.groupdict().get("method") or "GET").upper()
            add_candidate(match.group("value"), method, "javascript-http", False, match.end("value"))

    for pattern in URL_CONTEXT_PATTERNS:
        for match in pattern.finditer(content):
            add_candidate(match.group("value"), "UNKNOWN", "javascript-url", False, match.end("value"))

    for pattern in ROUTE_CONFIG_PATTERNS:
        for match in pattern.finditer(content):
            add_candidate(match.group("value"), "UNKNOWN", "javascript-router", True, match.end("value"))

    for match in QUOTED_STRING_PATTERN.finditer(content):
        value = decode_js_literal(match.group(0))
        if not looks_like_route(value, route_context=False):
            continue
        category, _ = classify_route(value)
        if category == "Application" and not value.startswith(("/", "./", "../", "#/", "http://", "https://")):
            continue
        add_candidate(match.group(0), "UNKNOWN", "javascript-string", False, match.end())

    for source_map in SOURCE_MAP_PATTERN.findall(content):
        add_finding(
            findings,
            title="Source map JavaScript referencee",
            category="Information Disclosure",
            severity="low",
            confidence="possible",
            tool="JavaScript analysis",
            evidence=f"{source_name} -> {source_map}",
            description="Une source map accessible peut faciliter la lecture du code client.",
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
                evidence=f"Motif trouve dans {source_name}",
                description="Indice a analyser manuellement ; il ne confirme pas une vulnerabilite.",
            )


def analyse_javascript(
    target: str,
    directory: Path,
    downloaded: list[dict[str, str]],
    inline_scripts: list[tuple[str, str]],
    findings: list[dict[str, Any]],
    add_finding: Callable[..., None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    log("Extraction contextuelle des routes dans le JavaScript")
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []

    for item in downloaded:
        content = (directory / item["file"]).read_text(encoding="utf-8", errors="replace")
        extract_routes_from_js(
            target=target,
            source_name=item["url"],
            content=content,
            endpoints=endpoints,
            parameters=parameters,
            findings=findings,
            add_finding=add_finding,
        )

    for source_name, content in inline_scripts:
        extract_routes_from_js(
            target=target,
            source_name=source_name,
            content=content,
            endpoints=endpoints,
            parameters=parameters,
            findings=findings,
            add_finding=add_finding,
        )

    log_ok(f"{len(endpoints)} route(s) brute(s) extraite(s) du JavaScript.")
    return endpoints, parameters


def routes_from_gobuster(target: str, directory: Path) -> list[dict[str, Any]]:
    endpoints: list[dict[str, Any]] = []
    content = (directory / "gobuster.txt").read_text(encoding="utf-8", errors="replace") if (directory / "gobuster.txt").exists() else ""
    for line in content.splitlines():
        match = re.search(r"^(\S+)\s+\(Status:\s*(\d{3})\)", line.strip())
        if not match:
            continue
        path, status_text = match.groups()
        route = normalize_route(path if path.startswith("/") else f"/{path}", target)
        if route:
            endpoints.append(endpoint_record(route, "GET", "gobuster", status=int(status_text)))
    return endpoints


def parse_robots_and_sitemap(target: str, findings: list[dict[str, Any]], add_finding: Callable[..., None]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    log("Lecture de robots.txt et sitemap.xml")
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []

    robots = request_url(urljoin(f"{target}/", "/robots.txt"))
    if robots.status == 200 and robots.body:
        for line in robots.body.splitlines():
            match = re.match(r"\s*(?:Allow|Disallow)\s*:\s*(\S+)", line, re.I)
            if not match or match.group(1) in {"", "/"}:
                continue
            route = normalize_route(match.group(1), target)
            if route:
                endpoints.append(endpoint_record(route, "UNKNOWN", "robots.txt"))
                parameters.extend(parameters_from_route(route, "UNKNOWN", "robots.txt"))
        add_finding(
            findings,
            title="robots.txt accessible",
            category="Content Discovery",
            severity="info",
            confidence="confirmed",
            tool="Route discovery",
            evidence="/robots.txt retourne HTTP 200",
            description="Les chemins indiques dans robots.txt ont ete ajoutes a la cartographie.",
        )

    sitemap = request_url(urljoin(f"{target}/", "/sitemap.xml"))
    if sitemap.status == 200 and sitemap.body:
        for value in re.findall(r"<loc>\s*(.*?)\s*</loc>", sitemap.body, re.I | re.S):
            route = normalize_route(html_lib.unescape(value), target)
            if route:
                endpoints.append(endpoint_record(route, "GET", "sitemap.xml"))
                parameters.extend(parameters_from_route(route, "GET", "sitemap.xml"))

    log_ok("Sources robots.txt et sitemap.xml analysees.")
    return endpoints, parameters


def load_path_file(path: Path) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    if not path.exists():
        return entries
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            category, route = line.split("|", 1)
        else:
            category, route = "Route sensible", line
        route = route.strip()
        if route:
            entries.append((category.strip() or "Route sensible", route))
    return entries


def detect_profile(profile: str, root_text: str, downloaded: list[dict[str, str]], directory: Path) -> list[str]:
    if profile == "none":
        return []
    if profile != "auto":
        return [profile]

    sample = root_text[:200_000].lower()
    for item in downloaded[:10]:
        sample += (directory / item["file"]).read_text(encoding="utf-8", errors="replace")[:150_000].lower()
    if "juice shop" in sample or "juice-shop" in sample or "owasp juice" in sample:
        return ["juice-shop"]
    return []


def profile_routes(config_dir: Path, profiles: list[str]) -> list[tuple[str, str, str]]:
    entries: list[tuple[str, str, str]] = []
    for category, route in load_path_file(config_dir / "sensitive-paths.txt"):
        entries.append((category, route, "global-profile"))
    for profile in profiles:
        for category, route in load_path_file(config_dir / "profiles" / f"{profile}.txt"):
            entries.append((category, route, f"profile:{profile}"))
    return entries


def probe_routes(
    *,
    target: str,
    candidates: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    add_finding: Callable[..., None],
) -> list[dict[str, Any]]:
    log("Verification HTTP non destructive des routes sensibles")
    baseline = request_url(urljoin(f"{target}/", f"/__scanner_missing_{int(time.time())}_9f3d"))
    results: list[dict[str, Any]] = []
    probed = 0

    for candidate in candidates:
        if probed >= MAX_PROBED_ROUTES:
            log_warn(f"Limite de {MAX_PROBED_ROUTES} routes testees atteinte.")
            break
        path = candidate["path"]
        if candidate.get("kind") == "client" or "{" in path or path.startswith("/#/"):
            results.append({**candidate, "status": None, "accessible": None, "note": "route cliente ou dynamique"})
            continue

        clean_path = path
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = urljoin(f"{target}/", path.lstrip("/"))
        if not same_origin(url, target):
            continue

        result = request_url(url)
        probed += 1
        fallback = result.status != 0 and equivalent_to_baseline(result, baseline)
        accessible = result.status in {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403} and not fallback
        record = {
            **candidate,
            "status": result.status,
            "content_type": result.headers.get("content-type", ""),
            "length": len(result.body),
            "location": result.headers.get("location", ""),
            "accessible": accessible,
            "spa_fallback": fallback,
            "error": result.error,
        }
        results.append(record)

        if not accessible:
            continue
        if result.status == 200 and candidate.get("sensitivity") in {"high", "medium"}:
            severity = "medium" if candidate.get("sensitivity") == "high" else "low"
            add_finding(
                findings,
                title="Route sensible accessible",
                category=candidate.get("category", "Content Discovery"),
                severity=severity,
                confidence="possible",
                tool="Sensitive route probe",
                evidence=f"GET {clean_path} -> HTTP {result.status} ({len(result.body)} octets)",
                description="La route repond sans authentification visible. Son contenu doit etre examine manuellement.",
            )
        elif result.status in {401, 403}:
            add_finding(
                findings,
                title="Route sensible protegee detectee",
                category=candidate.get("category", "Content Discovery"),
                severity="info",
                confidence="confirmed",
                tool="Sensitive route probe",
                evidence=f"GET {clean_path} -> HTTP {result.status}",
                description="La route existe vraisemblablement et applique un controle d'acces.",
            )

    log_ok(f"{probed} route(s) serveur testee(s), {sum(1 for item in results if item.get('accessible'))} route(s) distincte(s) detectee(s).")
    return results


def deduplicate_records(records: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for record in records:
        fingerprint = tuple(record.get(key) for key in keys)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        result.append(record)
    return result


def merge_endpoint_sources(endpoints: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for endpoint in endpoints:
        method = endpoint.get("method", "UNKNOWN")
        path = endpoint.get("path", "")
        kind = endpoint.get("kind", "server")
        if not path:
            continue
        key = (method, path, kind)
        if key not in merged:
            merged[key] = dict(endpoint)
            merged[key]["sources"] = [endpoint.get("source", "unknown")]
        else:
            source = endpoint.get("source", "unknown")
            if source not in merged[key]["sources"]:
                merged[key]["sources"].append(source)
            if endpoint.get("status") is not None:
                merged[key]["status"] = endpoint.get("status")

    # Une route UNKNOWN est absorbee lorsqu'une methode concrete existe pour le meme chemin.
    for key in list(merged):
        method, path, kind = key
        if method != "UNKNOWN":
            continue
        concrete = [candidate for candidate in merged if candidate[1:] == (path, kind) and candidate[0] != "UNKNOWN"]
        if len(concrete) == 1:
            target_key = concrete[0]
            for source in merged[key].get("sources", []):
                if source not in merged[target_key]["sources"]:
                    merged[target_key]["sources"].append(source)
            del merged[key]

    output = []
    for item in merged.values():
        item["source"] = ", ".join(item.pop("sources"))
        output.append(item)
    return sorted(output, key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item.get("sensitivity", "low"), 3), item["path"], item["method"]))


def discover_surface(
    *,
    target: str,
    directory: Path,
    config_dir: Path,
    profile: str,
    findings: list[dict[str, Any]],
    add_finding: Callable[..., None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    html_endpoints, html_parameters, script_urls, inline_scripts, pages, root_text = crawl_site(target)
    (directory / "crawl-pages.json").write_text(json.dumps(pages, indent=2, ensure_ascii=False), encoding="utf-8")

    downloaded = download_javascript(target, directory, script_urls)
    js_endpoints, js_parameters = analyse_javascript(
        target, directory, downloaded, inline_scripts, findings, add_finding
    )
    robots_endpoints, robots_parameters = parse_robots_and_sitemap(target, findings, add_finding)
    gobuster_endpoints = routes_from_gobuster(target, directory)

    profiles = detect_profile(profile, root_text, downloaded, directory)
    if profiles:
        log_ok(f"Profil(s) applique(s) : {', '.join(profiles)}")
    else:
        log("Aucun profil applicatif specifique applique.")

    configured_endpoints: list[dict[str, Any]] = []
    configured_parameters: list[dict[str, Any]] = []
    for category, raw_route, source in profile_routes(config_dir, profiles):
        route = normalize_route(raw_route, target, route_context=raw_route.startswith(("#/", "/#/")))
        if not route:
            continue
        if category:
            route["category"] = category
            if route["sensitivity"] == "low":
                route["sensitivity"] = "medium"
        endpoint = endpoint_record(route, "GET", source)
        configured_endpoints.append(endpoint)
        configured_parameters.extend(parameters_from_route(route, "GET", source))

    all_endpoints = merge_endpoint_sources(
        html_endpoints + js_endpoints + robots_endpoints + gobuster_endpoints + configured_endpoints
    )
    all_parameters = deduplicate_records(
        html_parameters + js_parameters + robots_parameters + configured_parameters,
        ("method", "path", "name", "location"),
    )

    sensitive_candidates = [item for item in all_endpoints if item.get("sensitivity") in {"high", "medium"}]
    probe_results = probe_routes(
        target=target,
        candidates=sensitive_candidates,
        findings=findings,
        add_finding=add_finding,
    )

    status_by_path = {(item.get("path"), item.get("method")): item for item in probe_results}
    for endpoint in all_endpoints:
        probe = status_by_path.get((endpoint.get("path"), endpoint.get("method")))
        if probe:
            for key in ("status", "accessible", "spa_fallback", "content_type", "length", "location"):
                if key in probe:
                    endpoint[key] = probe[key]

    def observed_source(source: str) -> bool:
        return any(not (part.strip() == "global-profile" or part.strip().startswith("profile:")) for part in source.split(","))

    filtered_endpoints: list[dict[str, Any]] = []
    for endpoint in all_endpoints:
        source = endpoint.get("source", "")
        if observed_source(source):
            filtered_endpoints.append(endpoint)
        elif endpoint.get("accessible") is True:
            filtered_endpoints.append(endpoint)
        elif endpoint.get("kind") == "client" and source.startswith("profile:"):
            filtered_endpoints.append(endpoint)

    kept_routes = {(item.get("method"), split_route_query(item.get("path", ""))[0]) for item in filtered_endpoints}
    filtered_parameters = [
        item for item in all_parameters
        if (item.get("method"), item.get("path")) in kept_routes
        or ("UNKNOWN", item.get("path")) in kept_routes
        or ("GET", item.get("path")) in kept_routes
    ]

    sensitive_results = [
        item for item in probe_results
        if item.get("accessible") is True
        or item.get("kind") == "client"
        or (item.get("accessible") is None and observed_source(item.get("source", "")))
    ]

    (directory / "route-probes.json").write_text(
        json.dumps(probe_results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (directory / "sensitive-routes.json").write_text(
        json.dumps(sensitive_results, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log_ok(f"Inventaire consolide : {len(filtered_endpoints)} endpoint(s), {len(filtered_parameters)} parametre(s), {len(sensitive_results)} route(s) sensible(s) detectee(s).")
    return filtered_endpoints, filtered_parameters, sensitive_results, profiles
