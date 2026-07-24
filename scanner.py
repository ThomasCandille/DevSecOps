#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import html
import json
import re
import shutil
import subprocess
import sys
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

VERSION = "2.1.0"
USER_AGENT = f"DevSecOps-Scanner/{VERSION}"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SUCCESS_CODES = {200, 201, 202, 204}
EXISTING_CODES = SUCCESS_CODES | {301, 302, 303, 307, 308, 401, 403, 405}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SQL_ERROR_PATTERNS = re.compile(
    r"SQL syntax|SQLITE_ERROR|SQLSTATE|Sequelize|mysql_fetch|mysqli?|PostgreSQL|pg_query|ORA-\d+|"
    r"unterminated quoted string|database error|syntax error at or near|unclosed quotation mark",
    re.IGNORECASE,
)
STACK_TRACE_PATTERNS = re.compile(
    r"Traceback \(most recent call last\)|(?:Exception|Error):\s|at [\w.$]+\([^\n]+:\d+\)|"
    r"/usr/(?:src|local)/|[A-Za-z]:\\[^\r\n]+\\",
    re.IGNORECASE,
)
SENSITIVE_RESPONSE_PATTERNS = {
    "Cle privee exposee": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Jeton JWT expose": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Secret potentiel expose": re.compile(
        r"(?i)(?:api[_-]?key|client[_-]?secret|access[_-]?token|password)\s*[:=]\s*['\"][^'\"]{8,}"
    ),
}
SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api", "/api/", "/rest", "/rest/",
    "/graphql", "/swagger.json", "/openapi.json", "/api-docs", "/v3/api-docs", "/admin", "/administrator",
    "/login", "/debug", "/metrics", "/health", "/status", "/actuator", "/actuator/health", "/actuator/env",
    "/files", "/ftp", "/uploads", "/backup", "/backups", "/.git/HEAD", "/.env", "/src",
]
JUICE_SHOP_PATHS = [
    "/ftp/", "/ftp/package.json.bak", "/metrics", "/api/Challenges", "/rest/admin/application-version",
    "/rest/products/search?q=apple", "/rest/user/login", "/api/Products", "/api/Users",
]
DANGEROUS_REPLAY_WORDS = {
    "delete", "remove", "checkout", "payment", "purchase", "order", "upload", "reset-password",
    "change-password", "transfer", "admin", "logout", "signout", "terminate", "cancel", "refund",
}
SENSITIVE_RESOURCE_WORDS = {
    "account", "address", "admin", "basket", "cart", "document", "invoice", "message", "order", "payment",
    "profile", "receipt", "report", "user", "wallet", "private", "download", "file",
}
REDIRECT_PARAMETER_RE = re.compile(r"url|uri|redirect|return|next|continue|destination|callback", re.I)
CSRF_PARAMETER_RE = re.compile(r"csrf|xsrf|anti.?forgery|request.?verification.?token", re.I)
AUTH_HEADER_NAMES = {"authorization", "cookie"}


@dataclass
class Finding:
    title: str
    severity: str
    category: str
    confidence: str
    evidence: str
    interpretation: str
    source: str
    url: str = ""


@dataclass
class Endpoint:
    method: str
    url: str
    source: str
    status: int | None = None
    confirmed: bool = False
    parameters: list[str] = field(default_factory=list)
    parameter_locations: dict[str, str] = field(default_factory=dict)


@dataclass
class ReplayRequest:
    label: str
    method: str
    url: str
    headers: dict[str, str]
    body: bytes | None
    mime_type: str
    parameters: list[str]
    response_status: int | None = None
    response_text: str = ""


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed: float
    error: str = ""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def signature(self) -> str:
        sample = self.body[:12000]
        return hashlib.sha256(sample).hexdigest()[:16] + f":{len(self.body)}:{self.status}"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


class DiscoveryParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: set[str] = set()
        self.scripts: set[str] = set()
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None
        self.title = ""
        self._in_title = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {key.lower(): value or "" for key, value in attrs}
        if tag in {"a", "link"} and data.get("href"):
            self.links.add(data["href"])
        if tag == "script" and data.get("src"):
            self.scripts.add(data["src"])
        if tag == "form":
            self._form = {
                "action": data.get("action", ""),
                "method": data.get("method", "GET").upper(),
                "parameters": [],
                "hidden": {},
            }
        if tag in {"input", "textarea", "select", "button"} and self._form is not None and data.get("name"):
            self._form["parameters"].append(data["name"])
            if data.get("type", "").lower() == "hidden":
                self._form["hidden"][data["name"]] = data.get("value", "")
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


class Scanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.target = normalize_url(args.target)
        parts = urlsplit(self.target)
        self.origin = f"{parts.scheme}://{parts.netloc}"
        self.host = parts.hostname or "target"
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        slug = re.sub(r"[^A-Za-z0-9]+", "-", f"{self.host}-{self.port}").strip("-").lower()
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        mode = "active" if args.active else "passive"
        self.output = Path(args.output or "results") / slug / f"{timestamp}_{mode}_{uuid.uuid4().hex[:8]}"
        self.raw = self.output / "raw"
        self.output.mkdir(parents=True, exist_ok=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        self.log_file = self.output / "console.log"
        self.findings: list[Finding] = []
        self.endpoints: dict[tuple[str, str], Endpoint] = {}
        self.replay_requests: dict[str, list[ReplayRequest]] = {"main": [], "user-a": [], "user-b": []}
        self.tools: dict[str, str] = {}
        self.coverage: dict[str, str] = {}
        self.active_tests = 0
        self.profile = "global"
        self.page_title = ""
        self.forms: list[dict[str, Any]] = []
        self.openapi_sources: list[str] = []
        self.graphql_endpoints: set[str] = set()
        self.started = time.monotonic()
        self.cookie_jar = CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar))
        self.no_redirect_opener = build_opener(HTTPCookieProcessor(self.cookie_jar), NoRedirect())

    def log(self, level: str, message: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] [{level}] {message}"
        print(line, flush=True)
        with self.log_file.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")

    def phase(self, number: int, total: int, message: str) -> None:
        self.log(f"{number}/{total}", message)

    def add_finding(self, finding: Finding) -> None:
        key = (finding.title.lower(), normalize_url_soft(finding.url), finding.evidence[:180])
        existing = {
            (item.title.lower(), normalize_url_soft(item.url), item.evidence[:180])
            for item in self.findings
        }
        if key not in existing:
            self.findings.append(finding)
            self.log("FINDING", f"{finding.severity.upper()} - {finding.title}")

    def add_endpoint(
        self,
        method: str,
        url: str,
        source: str,
        status: int | None = None,
        confirmed: bool = False,
        parameters: Iterable[str] | None = None,
        locations: dict[str, str] | None = None,
    ) -> Endpoint:
        absolute = normalize_url(urljoin(self.target, url))
        if not same_origin(self.target, absolute):
            return Endpoint(method, absolute, source, status, False)
        key = (method.upper(), absolute)
        endpoint = self.endpoints.get(key)
        if endpoint is None:
            query_names = {name for name, _ in parse_qsl(urlsplit(absolute).query, keep_blank_values=True)}
            endpoint = Endpoint(method.upper(), absolute, source, status, confirmed, sorted(query_names))
            endpoint.parameter_locations.update({name: "query" for name in query_names})
            self.endpoints[key] = endpoint
        else:
            endpoint.confirmed = endpoint.confirmed or confirmed
            endpoint.status = endpoint.status if endpoint.status is not None else status
        if parameters:
            endpoint.parameters = sorted(set(endpoint.parameters) | {item for item in parameters if item})
        if locations:
            endpoint.parameter_locations.update(locations)
        return endpoint

    def request(
        self,
        url: str,
        method: str = "GET",
        data: bytes | None = None,
        headers: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> HttpResult:
        encoded = encode_url(url)
        request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
        if headers:
            request_headers.update(headers)
        request = Request(encoded, data=data, headers=request_headers, method=method)
        started = time.monotonic()
        opener = self.opener if follow_redirects else self.no_redirect_opener
        try:
            with opener.open(request, timeout=self.args.timeout) as response:
                body = response.read(self.args.max_body)
                return HttpResult(
                    response.geturl(), response.status,
                    {key.lower(): value for key, value in response.headers.items()},
                    body, time.monotonic() - started,
                )
        except HTTPError as error:
            body = error.read(self.args.max_body)
            return HttpResult(
                encoded, error.code,
                {key.lower(): value for key, value in error.headers.items()},
                body, time.monotonic() - started, str(error),
            )
        except (URLError, TimeoutError, OSError, ValueError, UnicodeError) as error:
            return HttpResult(encoded, 0, {}, b"", time.monotonic() - started, str(error))

    def run_tool(self, name: str, command: list[str], timeout: int = 600) -> str:
        executable = shutil.which(command[0])
        if executable is None:
            self.tools[name] = "missing"
            self.log("WARN", f"{name} absent, module ignore.")
            return ""
        command[0] = executable
        output_path = self.raw / f"{name}.txt"
        self.log("INFO", f"Execution de {name}: {' '.join(command[:4])}{' ...' if len(command) > 4 else ''}")
        started = time.monotonic()
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
            text = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
            output_path.write_text(text, encoding="utf-8", errors="replace")
            self.tools[name] = "success" if result.returncode in {0, 1, 2} else f"exit-{result.returncode}"
            self.log("OK", f"{name} termine en {time.monotonic() - started:.1f}s.")
            return text
        except subprocess.TimeoutExpired as error:
            stdout = error.stdout.decode(errors="replace") if isinstance(error.stdout, bytes) else (error.stdout or "")
            stderr = error.stderr.decode(errors="replace") if isinstance(error.stderr, bytes) else (error.stderr or "")
            text = stdout + ("\n" + stderr if stderr else "") + "\nTIMEOUT"
            output_path.write_text(text, encoding="utf-8", errors="replace")
            self.tools[name] = "timeout"
            self.log("WARN", f"{name} interrompu apres {timeout}s.")
            return text

    # ------------------------------------------------------------------
    # Reconnaissance et analyse HTTP
    # ------------------------------------------------------------------

    def reconnaissance(self) -> None:
        self.coverage["Reconnaissance Kali"] = "executee"
        self.run_tool("whatweb", ["whatweb", "-a", "1", self.target], 120)
        self.run_tool("nmap", ["nmap", "-Pn", "-sV", "-p", str(self.port), self.host], 180)
        wordlist = first_existing([
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ])
        if wordlist:
            random_url = urljoin(self.target + "/", f"not-found-{uuid.uuid4().hex}")
            baseline = self.request(random_url)
            command = [
                "gobuster", "dir", "-u", self.target, "-w", wordlist,
                "-t", "5", "--timeout", f"{self.args.timeout}s", "-q",
            ]
            if baseline.body:
                command.extend(["--exclude-length", str(len(baseline.body))])
            self.parse_gobuster(self.run_tool("gobuster", command, 300))
        else:
            self.tools["gobuster"] = "no-wordlist"
            self.log("WARN", "Gobuster ignore: aucune wordlist commune trouvee.")
        self.parse_nikto(
            self.run_tool("nikto", ["nikto", "-h", self.target, "-nointeractive", "-maxtime", "5m"], 360)
        )

    def parse_gobuster(self, text: str) -> None:
        for line in text.splitlines():
            match = re.search(r"^/?([^\s]+)\s+\(Status:\s*(\d+)\)", line.strip())
            if match:
                path = "/" + match.group(1).lstrip("/")
                status = int(match.group(2))
                self.add_endpoint("GET", path, "gobuster", status, status not in {404, 0})

    def parse_nikto(self, text: str) -> None:
        for line in text.splitlines():
            clean = line.strip("+ ")
            lower = clean.lower()
            if not clean.startswith("["):
                continue
            if "header missing" in lower or "header is not set" in lower:
                self.add_finding(Finding(
                    "Header de securite manquant", "low", "Security Misconfiguration", "confirmed",
                    clean[:400], "Nikto signale une politique HTTP absente ou insuffisante.", "Nikto", self.target,
                ))
            elif "might be interesting" in lower:
                self.add_finding(Finding(
                    "Ressource potentiellement sensible", "low", "Content Discovery", "possible",
                    clean[:400], "La ressource doit etre analysee manuellement.", "Nikto", self.target,
                ))

    def initial_http_analysis(self) -> HttpResult:
        self.coverage["Headers, cookies, CORS et methodes"] = "executee"
        result = self.request(self.target)
        if result.status == 0:
            raise RuntimeError(f"Cible inaccessible: {result.error}")
        (self.raw / "home.html").write_bytes(result.body)
        (self.raw / "headers.json").write_text(
            json.dumps(result.headers, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        self.add_endpoint("GET", self.target, "initial", result.status, True)
        required = {
            "content-security-policy": (
                "Content-Security-Policy absent", "low",
                "Peut augmenter l'impact de certaines injections cote navigateur.",
            ),
            "x-content-type-options": (
                "X-Content-Type-Options absent", "low",
                "Le navigateur peut interpreter un contenu avec un type inattendu.",
            ),
            "referrer-policy": (
                "Referrer-Policy absent", "low",
                "Des informations d'URL peuvent etre transmises a d'autres sites.",
            ),
            "permissions-policy": (
                "Permissions-Policy absent", "info",
                "Les fonctions du navigateur ne sont pas explicitement restreintes.",
            ),
        }
        for header, (title, severity, interpretation) in required.items():
            if header not in result.headers:
                self.add_finding(Finding(
                    title, severity, "Security Misconfiguration", "confirmed",
                    f"Header {header} absent.", interpretation, "HTTP", self.target,
                ))
        if self.target.startswith("https://") and "strict-transport-security" not in result.headers:
            self.add_finding(Finding(
                "Strict-Transport-Security absent", "low", "Cryptographic Issues", "confirmed",
                "Header HSTS absent sur une cible HTTPS.",
                "Le navigateur n'est pas force a reutiliser HTTPS.", "HTTP", self.target,
            ))
        if result.headers.get("server"):
            self.add_finding(Finding(
                "Technologie serveur exposee", "info", "Information Disclosure", "confirmed",
                f"Server: {result.headers['server']}", "Cette information facilite la reconnaissance.", "HTTP", self.target,
            ))
        for cookie in self.cookie_jar:
            missing = []
            if not cookie.secure:
                missing.append("Secure")
            rest = {str(key).lower(): value for key, value in cookie._rest.items()}  # noqa: SLF001
            if "httponly" not in rest:
                missing.append("HttpOnly")
            if "samesite" not in rest:
                missing.append("SameSite")
            if missing:
                self.add_finding(Finding(
                    "Cookie insuffisamment protege", "medium", "Session Management", "confirmed",
                    f"Cookie {cookie.name}: attributs absents {', '.join(missing)}.",
                    "Les protections du cookie de session doivent etre verifiees.", "HTTP", self.target,
                ))
        self.check_cors_and_methods()
        self.scan_sensitive_content(result, self.target, "HTTP")
        return result

    def check_cors_and_methods(self) -> None:
        headers = {
            "Origin": "https://scanner.invalid",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization, Content-Type",
        }
        result = self.request(self.target, method="OPTIONS", headers=headers, follow_redirects=False)
        allow_origin = result.headers.get("access-control-allow-origin", "")
        credentials = result.headers.get("access-control-allow-credentials", "").lower() == "true"
        if allow_origin == "https://scanner.invalid" and credentials:
            self.add_finding(Finding(
                "CORS reflete une origine externe avec credentials", "high", "Security Misconfiguration", "confirmed",
                f"Access-Control-Allow-Origin: {allow_origin}; credentials=true",
                "Une origine externe peut potentiellement lire des reponses authentifiees.", "HTTP OPTIONS", self.target,
            ))
        elif allow_origin == "*" and credentials:
            self.add_finding(Finding(
                "Configuration CORS incoherente", "medium", "Security Misconfiguration", "confirmed",
                "Access-Control-Allow-Origin: * avec credentials=true",
                "La politique CORS doit etre revue, meme si les navigateurs bloquent certaines combinaisons.",
                "HTTP OPTIONS", self.target,
            ))
        allowed = result.headers.get("allow", "") or result.headers.get("access-control-allow-methods", "")
        if allowed:
            methods = {item.strip().upper() for item in allowed.split(",")}
            if "TRACE" in methods:
                self.add_finding(Finding(
                    "Methode HTTP TRACE annoncee", "low", "Security Misconfiguration", "confirmed",
                    f"Methodes annoncees: {allowed}", "TRACE est rarement necessaire sur une application web.",
                    "HTTP OPTIONS", self.target,
                ))

    def scan_sensitive_content(self, result: HttpResult, url: str, source: str) -> None:
        text = result.text[:500000]
        if STACK_TRACE_PATTERNS.search(text):
            self.add_finding(Finding(
                "Erreur technique detaillee exposee", "medium", "Information Disclosure", "probable",
                "Une stack trace ou un chemin interne apparait dans la reponse.",
                "Les erreurs techniques peuvent exposer l'architecture interne.", source, url,
            ))
        for title, pattern in SENSITIVE_RESPONSE_PATTERNS.items():
            if pattern.search(text):
                severity = "critical" if "privee" in title.lower() else "medium"
                self.add_finding(Finding(
                    title, severity, "Sensitive Data Exposure", "possible",
                    f"Motif sensible detecte dans la reponse de {url}.",
                    "La valeur doit etre verifiee et masquee dans le rapport final.", source, url,
                ))

    # ------------------------------------------------------------------
    # Cartographie HTML / JavaScript / API
    # ------------------------------------------------------------------

    def crawl(self, home: HttpResult) -> tuple[list[str], list[dict[str, Any]]]:
        self.coverage["Crawl HTML"] = "execute"
        queue: deque[tuple[str, int]] = deque([(self.target, 0)])
        visited: set[str] = set()
        scripts: set[str] = set()
        forms: list[dict[str, Any]] = []
        all_text = home.text
        while queue and len(visited) < self.args.max_pages:
            url, depth = queue.popleft()
            url = strip_fragment(url)
            if url in visited or not same_origin(self.target, url):
                continue
            visited.add(url)
            result = home if url == self.target else self.request(url)
            if result.status == 0:
                continue
            self.add_endpoint("GET", url, "crawl", result.status, result.status < 500)
            content_type = result.headers.get("content-type", "")
            if "html" not in content_type and not result.text.lstrip().startswith("<"):
                continue
            parser = DiscoveryParser()
            try:
                parser.feed(result.text)
            except Exception:
                pass
            if url == self.target:
                self.page_title = parser.title
            all_text += "\n" + result.text[:100000]
            for script in parser.scripts:
                script_url = urljoin(url, script)
                if same_origin(self.target, script_url):
                    scripts.add(strip_fragment(script_url))
            for form in parser.forms:
                action = urljoin(url, form["action"] or url)
                form["action"] = action
                forms.append(form)
                locations = {name: "form" for name in form["parameters"]}
                self.add_endpoint(
                    form["method"], action, "html-form", confirmed=True,
                    parameters=form["parameters"], locations=locations,
                )
                if form["method"] in STATE_CHANGING_METHODS and not any(
                    CSRF_PARAMETER_RE.search(name) for name in form["parameters"]
                ):
                    self.add_finding(Finding(
                        "Formulaire sans jeton CSRF visible", "low", "CSRF", "possible",
                        f"Formulaire {form['method']} vers {action} sans champ CSRF identifiable.",
                        "Les frameworks peuvent utiliser un header ou un cookie; une validation manuelle est necessaire.",
                        "HTML", action,
                    ))
            if depth < self.args.depth:
                for link in parser.links:
                    next_url = strip_fragment(urljoin(url, link))
                    if same_origin(self.target, next_url) and next_url not in visited:
                        queue.append((next_url, depth + 1))
        self.forms = forms
        self.log("OK", f"Crawl: {len(visited)} page(s), {len(scripts)} script(s), {len(forms)} formulaire(s).")
        self.fingerprint(all_text)
        return sorted(scripts), forms

    def fingerprint(self, text: str) -> None:
        lower = text.lower()
        if "juice shop" in lower or "owasp juice" in lower or "juiceshop" in lower:
            self.profile = "juice-shop"
        elif "universaltouchgamepad" in lower or "selkieslogoalt" in lower or "selkies" in lower:
            self.profile = "selkies"
        elif "wordpress" in lower or "wp-content" in lower:
            self.profile = "wordpress"
        if self.args.profile != "auto":
            self.profile = self.args.profile
        if self.profile == "selkies":
            self.add_finding(Finding(
                "La cible ne semble pas etre OWASP Juice Shop", "info", "Target Identification", "confirmed",
                "Empreinte Selkies/streaming detectee.",
                "Le port analyse expose probablement une autre application. Verifiez l'adresse reseau de Juice Shop.",
                "Fingerprint", self.target,
            ))
            self.log("WARN", "Empreinte Selkies detectee: cette cible ne ressemble pas a OWASP Juice Shop.")
        else:
            self.log("INFO", f"Profil applicatif detecte: {self.profile}.")

    def analyse_javascript(self, scripts: list[str]) -> None:
        self.coverage["Analyse JavaScript contextuelle"] = "executee"
        patterns = [
            (re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]", re.I), "GET", "javascript-fetch"),
            (re.compile(r"axios\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I), None, "javascript-axios"),
            (re.compile(r"\.open\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I), None, "javascript-xhr"),
            (
                re.compile(
                    r"['\"]((?:https?://[^'\"]+)?/(?:api|rest|auth|admin|graphql|metrics|ftp|files)"
                    r"(?:/[A-Za-z0-9_.{}:%-]+)*(?:\?[A-Za-z0-9_=&%{}.-]*)?)['\"]",
                    re.I,
                ),
                "UNKNOWN", "javascript-route",
            ),
        ]
        combined = ""
        downloaded = 0
        for index, script_url in enumerate(scripts[: self.args.max_scripts], start=1):
            result = self.request(script_url)
            if result.status != 200 or not result.body:
                continue
            downloaded += 1
            (self.raw / f"script-{index}.js").write_bytes(result.body)
            content = result.text
            combined += "\n" + content[:500000]
            if "localStorage" in content:
                self.add_finding(Finding(
                    "Stockage local utilise", "info", "Client-side Analysis", "possible",
                    f"localStorage trouve dans {script_url}",
                    "Verifier si des tokens ou donnees sensibles y sont stockes.", "JavaScript", script_url,
                ))
            if re.search(r"sourceMappingURL=", content):
                self.add_finding(Finding(
                    "Source map referencee", "low", "Information Disclosure", "possible",
                    f"Source map referencee dans {script_url}",
                    "Une source map accessible peut exposer le code source original.", "JavaScript", script_url,
                ))
            self.scan_sensitive_content(result, script_url, "JavaScript")
            for pattern, fixed_method, source in patterns:
                for match in pattern.finditer(content):
                    if source == "javascript-fetch":
                        method, route = fixed_method or "GET", match.group(1)
                    elif source in {"javascript-axios", "javascript-xhr"}:
                        method, route = match.group(1).upper(), match.group(2)
                    else:
                        method, route = fixed_method or "UNKNOWN", match.group(1)
                    if valid_route(route):
                        self.add_endpoint(method, route, source)
                        if "/graphql" in route.lower():
                            self.graphql_endpoints.add(normalize_url(urljoin(self.target, route)))
        if self.profile == "global" and combined:
            self.fingerprint(combined)
        self.log("OK", f"JavaScript: {downloaded} fichier(s) examine(s).")

    def import_openapi(self) -> None:
        sources: list[str] = []
        if self.args.openapi:
            sources.append(self.args.openapi)
        else:
            for path in ["/openapi.json", "/swagger.json", "/v3/api-docs"]:
                result = self.request(urljoin(self.target, path))
                if result.status == 200 and result.text.lstrip().startswith("{"):
                    sources.append(result.url)
                    break
        if not sources:
            self.coverage["OpenAPI"] = "non detecte"
            return
        imported = 0
        for source in sources:
            try:
                if re.match(r"^https?://", source, re.I):
                    result = self.request(source)
                    raw = result.text
                else:
                    raw = Path(source).read_text(encoding="utf-8")
                document = json.loads(raw)
            except (OSError, json.JSONDecodeError, ValueError) as error:
                self.log("WARN", f"Definition OpenAPI non importee ({source}): {error}")
                continue
            self.openapi_sources.append(source)
            for route, route_item in document.get("paths", {}).items():
                if not isinstance(route_item, dict):
                    continue
                shared_parameters = route_item.get("parameters", []) if isinstance(route_item.get("parameters"), list) else []
                for method, operation in route_item.items():
                    method_upper = method.upper()
                    if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                        continue
                    if not isinstance(operation, dict):
                        operation = {}
                    parameters: list[str] = []
                    locations: dict[str, str] = {}
                    for parameter in shared_parameters + operation.get("parameters", []):
                        if isinstance(parameter, dict) and parameter.get("name"):
                            name = str(parameter["name"])
                            parameters.append(name)
                            locations[name] = str(parameter.get("in", "unknown"))
                    request_body = operation.get("requestBody", {})
                    if isinstance(request_body, dict):
                        for media in request_body.get("content", {}).values():
                            schema = media.get("schema", {}) if isinstance(media, dict) else {}
                            for name in schema_property_names(schema):
                                parameters.append(name)
                                locations[name] = "json"
                    safe_route = substitute_path_parameters(route)
                    self.add_endpoint(
                        method_upper, safe_route, "openapi", parameters=parameters, locations=locations,
                    )
                    imported += 1
            self.log("OK", f"OpenAPI importe: {source}")
        self.coverage["OpenAPI"] = f"{imported} operation(s)"

    def probe_graphql(self) -> None:
        if self.args.graphql_url:
            self.graphql_endpoints.add(normalize_url(urljoin(self.target, self.args.graphql_url)))
        if not self.graphql_endpoints:
            for endpoint in self.endpoints.values():
                if "/graphql" in endpoint.url.lower():
                    self.graphql_endpoints.add(endpoint.url)
        if not self.graphql_endpoints:
            self.coverage["GraphQL"] = "non detecte"
            return
        tested = 0
        for endpoint_url in sorted(self.graphql_endpoints):
            payload = json.dumps({"query": "query ScannerTypeName { __typename }"}).encode()
            result = self.request(
                endpoint_url, method="POST", data=payload,
                headers={"Content-Type": "application/json"},
            )
            tested += 1
            self.add_endpoint("POST", endpoint_url, "graphql", result.status, result.status in EXISTING_CODES, ["query"], {"query": "json"})
            if result.status == 200 and '"data"' in result.text:
                self.add_finding(Finding(
                    "Endpoint GraphQL accessible", "info", "Attack Surface", "confirmed",
                    f"La requete __typename retourne HTTP {result.status}.",
                    "Le schema et les autorisations GraphQL doivent etre controles.", "GraphQL", endpoint_url,
                ))
            if self.args.graphql_introspection:
                introspection = json.dumps({"query": "query ScannerSchema { __schema { queryType { name } mutationType { name } } }"}).encode()
                result2 = self.request(
                    endpoint_url, method="POST", data=introspection,
                    headers={"Content-Type": "application/json"},
                )
                if result2.status == 200 and '"__schema"' in result2.text:
                    self.add_finding(Finding(
                        "Introspection GraphQL accessible", "low", "Information Disclosure", "confirmed",
                        "La requete __schema retourne des informations de schema.",
                        "L'introspection peut faciliter la reconnaissance; son exposition doit etre un choix explicite.",
                        "GraphQL", endpoint_url,
                    ))
        self.coverage["GraphQL"] = f"{tested} endpoint(s) teste(s)"

    # ------------------------------------------------------------------
    # HAR, JWT et requetes dynamiques
    # ------------------------------------------------------------------

    def import_hars(self) -> None:
        inputs = [
            ("main", self.args.har),
            ("user-a", self.args.har_user_a),
            ("user-b", self.args.har_user_b),
        ]
        imported_total = 0
        for label, value in inputs:
            if value:
                imported_total += self.import_har_file(label, Path(value))
        self.coverage["HAR"] = f"{imported_total} requete(s)" if imported_total else "non fourni"

    def import_har_file(self, label: str, path: Path) -> int:
        if not path.exists():
            self.log("WARN", f"HAR introuvable: {path}")
            return 0
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            self.log("WARN", f"HAR illisible: {error}")
            return 0
        count = 0
        for entry in data.get("log", {}).get("entries", []):
            request_data = entry.get("request", {})
            url = request_data.get("url", "")
            if not url or not same_origin(self.target, url):
                continue
            method = request_data.get("method", "GET").upper()
            headers_all = {
                item.get("name", "").lower(): item.get("value", "")
                for item in request_data.get("headers", []) if item.get("name")
            }
            safe_headers = {
                key: value for key, value in headers_all.items()
                if key in {"accept", "content-type", "origin", "referer", "x-csrf-token", "x-xsrf-token"}
            }
            if self.args.use_har_auth:
                safe_headers.update({key: value for key, value in headers_all.items() if key in AUTH_HEADER_NAMES})
            query_parameters = [
                item.get("name", "") for item in request_data.get("queryString", []) if item.get("name")
            ]
            locations = {name: "query" for name in query_parameters}
            post_data = request_data.get("postData", {}) or {}
            mime_type = str(post_data.get("mimeType", headers_all.get("content-type", "")))
            body_text = post_data.get("text", "") or ""
            body = body_text.encode("utf-8") if body_text else None
            body_parameters: list[str] = []
            for item in post_data.get("params", []) or []:
                if item.get("name"):
                    body_parameters.append(item["name"])
                    locations[item["name"]] = "form"
            if body_text and "json" in mime_type.lower():
                try:
                    body_parameters.extend(flatten_json_keys(json.loads(body_text)))
                    locations.update({name: "json" for name in body_parameters})
                except json.JSONDecodeError:
                    pass
            parameters = sorted(set(query_parameters + body_parameters))
            response = entry.get("response", {})
            response_content = response.get("content", {}) or {}
            response_text = response_content.get("text", "") or ""
            replay = ReplayRequest(
                label=label, method=method, url=normalize_url(url), headers=safe_headers,
                body=body, mime_type=mime_type, parameters=parameters,
                response_status=response.get("status"), response_text=response_text[:200000],
            )
            self.replay_requests[label].append(replay)
            self.add_endpoint(method, url, f"har-{label}", response.get("status"), True, parameters, locations)
            for header_name, header_value in headers_all.items():
                if header_name == "authorization" and header_value.lower().startswith("bearer "):
                    self.inspect_jwt(header_value.split(None, 1)[1], url)
            self.check_har_csrf(replay, headers_all)
            count += 1
        self.log("OK", f"HAR {label}: {count} requete(s) de la meme origine importee(s).")
        return count

    def check_har_csrf(self, replay: ReplayRequest, original_headers: dict[str, str]) -> None:
        if replay.method not in STATE_CHANGING_METHODS:
            return
        uses_cookie = "cookie" in original_headers
        has_token = any(CSRF_PARAMETER_RE.search(key) for key in original_headers)
        has_token = has_token or any(CSRF_PARAMETER_RE.search(name) for name in replay.parameters)
        if uses_cookie and not has_token:
            self.add_finding(Finding(
                "Requete authentifiee sans protection CSRF visible", "low", "CSRF", "possible",
                f"{replay.method} {replay.url} utilise un cookie sans token CSRF identifiable.",
                "SameSite ou une verification d'origine peuvent proteger la requete; validation manuelle requise.",
                "HAR", replay.url,
            ))

    def inspect_jwt(self, token: str, url: str) -> None:
        parts = token.split(".")
        if len(parts) != 3:
            return
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        except Exception:
            return
        algorithm = str(header.get("alg", ""))
        if algorithm.lower() == "none":
            self.add_finding(Finding(
                "JWT utilisant alg=none", "critical", "Broken Authentication", "confirmed",
                "Le header JWT declare alg=none.", "Le token peut ne pas etre signe.", "HAR/JWT", url,
            ))
        if "exp" not in payload:
            self.add_finding(Finding(
                "JWT sans expiration", "medium", "Broken Authentication", "confirmed",
                "Claim exp absent.", "Un token sans expiration peut rester valide trop longtemps.", "HAR/JWT", url,
            ))
        else:
            try:
                now = int(time.time())
                exp = int(payload["exp"])
                iat = int(payload.get("iat", now))
                if exp < now:
                    self.add_finding(Finding(
                        "JWT expire observe dans le trafic", "info", "Session Management", "confirmed",
                        "Le claim exp est anterieur a l'heure du scan.",
                        "Une session ou une capture HAR peut etre obsolete.", "HAR/JWT", url,
                    ))
                elif exp - iat > 30 * 24 * 3600:
                    self.add_finding(Finding(
                        "Duree de validite JWT elevee", "low", "Session Management", "possible",
                        f"Duree iat-exp: {exp - iat} secondes.",
                        "Une longue duree augmente l'impact d'un vol de token.", "HAR/JWT", url,
                    ))
            except (TypeError, ValueError):
                pass
        sensitive = [key for key in payload if re.search(r"password|secret|card|token", key, re.I)]
        if sensitive:
            self.add_finding(Finding(
                "Donnees potentiellement sensibles dans un JWT", "medium", "Sensitive Data Exposure", "possible",
                f"Claims sensibles: {', '.join(sensitive)}", "Le payload JWT est lisible par le client.", "HAR/JWT", url,
            ))

    # ------------------------------------------------------------------
    # Sondage et mutations actives
    # ------------------------------------------------------------------

    def probe_sensitive_paths(self) -> None:
        self.coverage["Routes sensibles"] = "executee"
        random_result = self.request(
            urljoin(self.target + "/", f"missing-{uuid.uuid4().hex}"), follow_redirects=False
        )
        paths = list(SENSITIVE_PATHS)
        if self.profile == "juice-shop":
            paths.extend(JUICE_SHOP_PATHS)
        confirmed = 0
        for path in dict.fromkeys(paths):
            result = self.request(urljoin(self.target + "/", path.lstrip("/")), follow_redirects=False)
            same_fallback = result.status == random_result.status and result.signature == random_result.signature
            exists = result.status in EXISTING_CODES and not same_fallback
            self.add_endpoint("GET", path, "sensitive-probe", result.status, exists)
            if not exists:
                continue
            confirmed += 1
            lower_path = path.lower()
            self.scan_sensitive_content(result, result.url, "Sensitive probe")
            if lower_path in {"/.env", "/.git/head"} and result.status == 200:
                self.add_finding(Finding(
                    "Fichier de configuration sensible expose", "critical", "Sensitive Data Exposure", "confirmed",
                    f"{path} retourne HTTP 200.", "Des secrets ou le code source peuvent etre exposes.",
                    "Active probe", result.url,
                ))
            elif "package.json.bak" in lower_path and result.status == 200:
                self.add_finding(Finding(
                    "Sauvegarde de dependances exposee", "high", "Sensitive Data Exposure", "confirmed",
                    f"{path} retourne HTTP 200.",
                    "Le fichier peut exposer versions, dependances et informations internes.",
                    "Juice Shop profile", result.url,
                ))
            elif lower_path in {"/metrics", "/actuator/env"} and result.status == 200:
                self.add_finding(Finding(
                    "Endpoint de diagnostic expose", "medium", "Security Misconfiguration", "confirmed",
                    f"{path} retourne HTTP 200.", "Des informations internes ou metriques sont accessibles.",
                    "Active probe", result.url,
                ))
            elif lower_path.startswith("/ftp") and result.status in {200, 301}:
                self.add_finding(Finding(
                    "Repertoire de fichiers accessible", "medium", "Sensitive Data Exposure", "confirmed",
                    f"{path} retourne HTTP {result.status}.",
                    "Verifier les documents et sauvegardes accessibles.", "Active probe", result.url,
                ))
        self.log("OK", f"Routes sensibles: {len(paths)} testee(s), {confirmed} distincte(s) detectee(s).")

    def active_mutations(self) -> None:
        if not self.args.active:
            self.coverage["Mutations actives"] = "non demandees"
            return
        tested = 0
        candidates = [
            endpoint for endpoint in self.endpoints.values()
            if endpoint.method in {"GET", "UNKNOWN"} and any(
                location == "query" for location in endpoint.parameter_locations.values()
            )
        ]
        self.log("INFO", f"Mutations GET: {len(candidates[: self.args.max_active])} endpoint(s).")
        for endpoint in candidates[: self.args.max_active]:
            parts = urlsplit(endpoint.url)
            original_pairs = parse_qsl(parts.query, keep_blank_values=True)
            original = dict(original_pairs)
            query_names = [name for name in endpoint.parameters if endpoint.parameter_locations.get(name) == "query"]
            for name in query_names[:3]:
                if name not in original:
                    continue
                baseline = self.request(endpoint.url, follow_redirects=False)
                self.test_mutation_set(endpoint.url, baseline, name, lambda value, follow=False: self.mutated_get(parts, original, name, value, follow))
                tested += 1
        if self.args.active_post:
            for replay in self.replay_requests["main"][: self.args.max_active]:
                if replay.method not in {"POST", "PUT", "PATCH"} or unsafe_replay_url(replay.url):
                    continue
                if not replay.parameters:
                    continue
                baseline = self.replay(replay)
                for name in replay.parameters[:2]:
                    result_factory = lambda value, follow=False, req=replay, param=name: self.mutated_replay(req, param, value, follow)
                    self.test_mutation_set(replay.url, baseline, name, result_factory)
                    tested += 1
                    if tested >= self.args.max_active:
                        break
                if tested >= self.args.max_active:
                    break
        self.coverage["Mutations actives"] = f"{tested} parametre(s)"

    def test_mutation_set(self, url: str, baseline: HttpResult, name: str, factory) -> None:  # noqa: ANN001
        marker = f"WSS_{uuid.uuid4().hex[:8]}"
        self.active_tests += 1
        reflected = factory(marker)
        if marker in reflected.text:
            context = reflection_context(reflected.text, marker)
            severity = "high" if context in {"script", "event-handler"} else "medium"
            self.add_finding(Finding(
                "Entree utilisateur reflechie", severity, "XSS", "probable",
                f"Le marqueur {marker} est renvoye par {name}; contexte: {context}.",
                "La reflexion ne confirme une XSS que si le contexte permet l'execution de script.",
                "Active mutation", url,
            ))
        self.active_tests += 1
        quoted = factory("scanner'\"<>")
        if SQL_ERROR_PATTERNS.search(quoted.text) and not SQL_ERROR_PATTERNS.search(baseline.text):
            self.add_finding(Finding(
                "Erreur SQL declenchee par une entree", "high", "Injection", "probable",
                f"Une erreur SQL apparait apres mutation du parametre {name}.",
                "Une injection SQL est possible et doit etre confirmee par un test cible.", "Active mutation", url,
            ))
        if baseline.status < 500 <= quoted.status:
            self.add_finding(Finding(
                "Erreur serveur provoquee par une entree", "medium", "Improper Input Validation", "confirmed",
                f"Le parametre {name} fait passer la reponse de HTTP {baseline.status} a {quoted.status}.",
                "La validation ou la gestion d'erreur est insuffisante.", "Active mutation", url,
            ))
        self.active_tests += 1
        oversized = factory("A" * 512)
        if baseline.status < 500 <= oversized.status or STACK_TRACE_PATTERNS.search(oversized.text):
            self.add_finding(Finding(
                "Entree longue mal geree", "medium", "Improper Input Validation", "probable",
                f"Une valeur de 512 caracteres sur {name} provoque une erreur ou une trace technique.",
                "La taille et le type des entrees doivent etre controles.", "Active mutation", url,
            ))
        if REDIRECT_PARAMETER_RE.search(name):
            self.active_tests += 1
            redirect = factory("https://scanner.invalid/", False)
            location = redirect.headers.get("location", "")
            if "scanner.invalid" in location:
                self.add_finding(Finding(
                    "Redirection externe non validee", "high", "Unvalidated Redirects", "confirmed",
                    f"Location: {location}", "Un attaquant peut rediriger un utilisateur vers un domaine externe.",
                    "Active mutation", url,
                ))

    def mutated_get(
        self, parts, original: dict[str, str], name: str, value: str, follow_redirects: bool = False  # noqa: ANN001
    ) -> HttpResult:
        query = dict(original)
        query[name] = value
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))
        return self.request(url, follow_redirects=follow_redirects)

    def replay(self, replay: ReplayRequest, follow_redirects: bool = False) -> HttpResult:
        return self.request(
            replay.url, method=replay.method, data=replay.body,
            headers=replay.headers, follow_redirects=follow_redirects,
        )

    def mutated_replay(
        self, replay: ReplayRequest, parameter: str, value: str, follow_redirects: bool = False
    ) -> HttpResult:
        url = replay.url
        body = replay.body
        headers = dict(replay.headers)
        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        if parameter in query:
            query[parameter] = value
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        elif body and "json" in replay.mime_type.lower():
            try:
                payload = json.loads(body.decode("utf-8", errors="replace"))
                if set_json_path(payload, parameter, value):
                    body = json.dumps(payload).encode()
                    headers["content-type"] = "application/json"
            except json.JSONDecodeError:
                pass
        elif body:
            form = dict(parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True))
            if parameter in form:
                form[parameter] = value
                body = urlencode(form).encode()
                headers["content-type"] = "application/x-www-form-urlencoded"
        return self.request(url, method=replay.method, data=body, headers=headers, follow_redirects=follow_redirects)

    # ------------------------------------------------------------------
    # Authentification, session et controles d'acces
    # ------------------------------------------------------------------

    def auth_tests(self) -> None:
        if not self.args.auth_config:
            self.coverage["Authentification / anti-automation"] = "configuration absente"
            return
        if not self.args.active:
            self.coverage["Authentification / anti-automation"] = "requiert --active"
            return
        try:
            config = json.loads(Path(self.args.auth_config).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            self.log("WARN", f"Configuration auth illisible: {error}")
            return
        login_url = normalize_url(urljoin(self.target, str(config.get("login_url", "/login"))))
        method = str(config.get("method", "POST")).upper()
        content_type = str(config.get("content_type", "application/json"))
        known = str(config.get("known_username", "scanner-known@example.invalid"))
        unknown = str(config.get("unknown_username", f"scanner-{uuid.uuid4().hex[:8]}@example.invalid"))
        password = str(config.get("wrong_password", "Scanner-Wrong-Password-123!"))
        template = config.get("body_template", {"email": "{username}", "password": "{password}"})
        attempts = min(max(int(config.get("attempts", 5)), 2), 8)

        def send(username: str) -> HttpResult:
            payload = replace_placeholders(copy.deepcopy(template), username, password)
            if "json" in content_type.lower():
                body = json.dumps(payload).encode()
            else:
                body = urlencode(payload).encode()
            return self.request(
                login_url, method=method, data=body,
                headers={"Content-Type": content_type}, follow_redirects=False,
            )

        known_result = send(known)
        unknown_result = send(unknown)
        similarity = response_similarity(known_result, unknown_result)
        if known_result.status != unknown_result.status or similarity < 0.75:
            self.add_finding(Finding(
                "Enumeration de comptes potentielle", "medium", "Broken Authentication", "probable",
                f"Compte connu: HTTP {known_result.status}; inconnu: HTTP {unknown_result.status}; similarite {similarity:.2f}.",
                "Les erreurs de connexion ne devraient pas reveler si un compte existe.", "Auth tests", login_url,
            ))
        results = []
        for _ in range(attempts):
            results.append(send(known))
        blocked = any(item.status == 429 for item in results)
        challenged = any(re.search(r"captcha|too many|rate limit|locked|temporarily", item.text, re.I) for item in results)
        delays = [item.elapsed for item in results]
        progressive_delay = len(delays) >= 3 and delays[-1] > max(delays[0] * 2, delays[0] + 1.0)
        if not blocked and not challenged and not progressive_delay:
            self.add_finding(Finding(
                "Protection anti-automatisation non observee", "low", "Broken Anti Automation", "possible",
                f"{attempts} echecs controles sans HTTP 429, challenge ni ralentissement progressif.",
                "Le test est volontairement limite et ne prouve pas l'absence totale de protection.",
                "Auth tests", login_url,
            ))
        self.coverage["Authentification / anti-automation"] = f"{attempts + 2} requetes"

    def access_control_tests(self) -> None:
        if not self.args.access_tests:
            self.coverage["Controle d'acces A/B/anonyme"] = "non demande"
            return
        if not self.args.use_har_auth:
            self.coverage["Controle d'acces A/B/anonyme"] = "requiert --use-har-auth"
            return
        user_a = self.replay_requests["user-a"]
        user_b = self.replay_requests["user-b"]
        if not user_a or not user_b:
            self.coverage["Controle d'acces A/B/anonyme"] = "HAR A/B manquants"
            return
        auth_a = session_headers(user_a)
        auth_b = session_headers(user_b)
        tested = 0
        for request_a in user_a:
            if request_a.method != "GET" or not is_sensitive_resource(request_a.url):
                continue
            if tested >= self.args.max_access_tests:
                break
            base_headers = {key: value for key, value in request_a.headers.items() if key not in AUTH_HEADER_NAMES}
            result_a = self.request(request_a.url, headers={**base_headers, **auth_a})
            result_b = self.request(request_a.url, headers={**base_headers, **auth_b})
            result_anon = self.request(request_a.url, headers=base_headers)
            tested += 1
            if result_a.status in SUCCESS_CODES:
                if result_b.status in SUCCESS_CODES and response_similarity(result_a, result_b) >= 0.90 and len(result_a.body) > 20:
                    self.add_finding(Finding(
                        "Ressource potentiellement accessible entre comptes", "high", "Broken Access Control", "probable",
                        f"Compte A et B obtiennent une reponse similaire sur {request_a.url}.",
                        "Verifier que la ressource appartient bien au compte A avant de confirmer un IDOR/BOLA.",
                        "Access control", request_a.url,
                    ))
                if result_anon.status in SUCCESS_CODES and response_similarity(result_a, result_anon) >= 0.90 and len(result_a.body) > 20:
                    self.add_finding(Finding(
                        "Ressource authentifiee potentiellement accessible anonymement", "high", "Broken Access Control", "probable",
                        f"La reponse anonyme est similaire a celle du compte A sur {request_a.url}.",
                        "La ressource doit etre verifiee pour confirmer qu'elle est privee.",
                        "Access control", request_a.url,
                    ))
        self.coverage["Controle d'acces A/B/anonyme"] = f"{tested} ressource(s)"

    def session_tests(self) -> None:
        if not self.args.session_tests:
            self.coverage["Invalidation de session"] = "non demandee"
            return
        if not self.args.use_har_auth:
            self.coverage["Invalidation de session"] = "requiert --use-har-auth"
            return
        user_a = self.replay_requests["user-a"]
        if not user_a:
            self.coverage["Invalidation de session"] = "HAR user A manquant"
            return
        logout = next((item for item in user_a if re.search(r"logout|signout|logoff", item.url, re.I)), None)
        protected = next((item for item in user_a if item.method == "GET" and is_sensitive_resource(item.url)), None)
        if not logout or not protected:
            self.coverage["Invalidation de session"] = "logout ou ressource protegee non identifies"
            return
        auth_headers = session_headers(user_a)
        protected_headers = {**protected.headers, **auth_headers}
        before = self.request(protected.url, headers=protected_headers)
        self.request(logout.url, method=logout.method, data=logout.body, headers={**logout.headers, **auth_headers}, follow_redirects=False)
        after = self.request(protected.url, headers=protected_headers)
        if before.status in SUCCESS_CODES and after.status in SUCCESS_CODES and response_similarity(before, after) >= 0.90:
            self.add_finding(Finding(
                "Session potentiellement encore valide apres deconnexion", "high", "Broken Authentication", "probable",
                f"La ressource {protected.url} reste accessible avec la session capturee apres logout.",
                "Certains JWT stateless ne sont pas revoques cote serveur; valider le comportement attendu.",
                "Session tests", protected.url,
            ))
        self.coverage["Invalidation de session"] = "1 scenario"

    def business_tests(self) -> None:
        if not self.args.business_config:
            self.coverage["Logique metier"] = "configuration absente"
            return
        if not self.args.active:
            self.coverage["Logique metier"] = "requiert --active"
            return
        try:
            config = json.loads(Path(self.args.business_config).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            self.log("WARN", f"Scenarios metier illisibles: {error}")
            return
        executed = 0
        for scenario in config.get("scenarios", []):
            if not scenario.get("enabled", False):
                continue
            name = str(scenario.get("name", f"Scenario {executed + 1}"))
            steps = scenario.get("steps", [])
            results: list[HttpResult] = []
            for step in steps[:10]:
                method = str(step.get("method", "GET")).upper()
                url = normalize_url(urljoin(self.target, str(step.get("url", "/"))))
                if not same_origin(self.target, url):
                    continue
                headers = {str(key): str(value) for key, value in step.get("headers", {}).items()}
                body: bytes | None = None
                if "json" in step:
                    body = json.dumps(step["json"]).encode()
                    headers.setdefault("Content-Type", "application/json")
                elif "form" in step:
                    body = urlencode(step["form"]).encode()
                    headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
                elif "body" in step:
                    body = str(step["body"]).encode()
                repeat = min(max(int(step.get("repeat", 1)), 1), 3)
                for _ in range(repeat):
                    results.append(self.request(url, method=method, data=body, headers=headers, follow_redirects=False))
            assertion = scenario.get("flag_if", {})
            if results and assertion:
                statuses = [item.status for item in results]
                all_success = all(status in SUCCESS_CODES for status in statuses)
                if assertion.get("all_requests_succeed") is True and all_success:
                    self.add_finding(Finding(
                        f"Scenario metier suspect: {name}", str(assertion.get("severity", "medium")),
                        "Business Logic", "possible",
                        f"Toutes les etapes/repetitions reussissent: {statuses}.",
                        str(assertion.get("interpretation", "Le comportement doit etre compare a la regle metier attendue.")),
                        "Business scenario", self.target,
                    ))
                forbidden = {int(value) for value in assertion.get("status_in", [])}
                if forbidden and any(status in forbidden for status in statuses):
                    self.add_finding(Finding(
                        f"Scenario metier detecte: {name}", str(assertion.get("severity", "medium")),
                        "Business Logic", "probable",
                        f"Statuts observes: {statuses}.",
                        str(assertion.get("interpretation", "Le scenario a satisfait la condition configuree.")),
                        "Business scenario", self.target,
                    ))
            executed += 1
        self.coverage["Logique metier"] = f"{executed} scenario(s)"

    # ------------------------------------------------------------------
    # Outils complementaires
    # ------------------------------------------------------------------

    def run_nuclei(self) -> None:
        if not self.args.active or not self.args.nuclei:
            self.tools["nuclei"] = "disabled"
            self.log("INFO", "Nuclei non demande : module ignore.")
            return
        if shutil.which("nuclei") is None:
            self.tools["nuclei"] = "missing"
            self.log("WARN", "Nuclei demande mais absent du systeme.")
            return
        command = [
            "nuclei", "-u", self.target, "-jsonl", "-severity", "medium,high,critical",
            "-rl", "10", "-timeout", "5", "-retries", "1", "-duc", "-silent",
            "-elog", str(self.raw / "nuclei-errors.log"),
        ]
        output = self.run_tool("nuclei", command, timeout=self.args.nuclei_timeout)
        detections = 0
        for line in output.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            severity = str(info.get("severity", "info")).lower()
            matched_url = item.get("matched-at") or item.get("host") or self.target
            self.add_finding(Finding(
                str(info.get("name", item.get("template-id", "Alerte Nuclei"))),
                severity if severity in SEVERITY_ORDER else "info", "Nuclei", "confirmed",
                matched_url, "Detection issue d'un template Nuclei.", "Nuclei", matched_url,
            ))
            detections += 1
        if self.tools.get("nuclei") == "timeout":
            self.log("WARN", f"Nuclei interrompu apres {self.args.nuclei_timeout}s; resultats partiels.")
        else:
            self.log("OK", f"Nuclei termine : {detections} detection(s).")

    def run_sqlmap(self) -> None:
        if not self.args.active or not self.args.sqlmap:
            self.tools["sqlmap"] = "disabled"
            self.log("INFO", "sqlmap non demande : module ignore.")
            return
        if shutil.which("sqlmap") is None:
            self.tools["sqlmap"] = "missing"
            self.log("WARN", "sqlmap demande mais absent.")
            return
        targets = [
            endpoint for endpoint in self.endpoints.values()
            if endpoint.method in {"GET", "UNKNOWN"} and any(
                location == "query" for location in endpoint.parameter_locations.values()
            )
        ]
        for index, endpoint in enumerate(targets[:2], start=1):
            parameter = next(
                (name for name in endpoint.parameters if endpoint.parameter_locations.get(name) == "query"), None
            )
            if not parameter:
                continue
            command = [
                "sqlmap", "-u", endpoint.url, "-p", parameter, "--batch", "--level", "1", "--risk", "1", "--smart",
                "--threads", "1", "--timeout", str(self.args.timeout), "--retries", "0", "--disable-coloring",
                "--output-dir", str(self.raw / f"sqlmap-{index}"),
            ]
            text = self.run_tool(f"sqlmap-{index}", command, self.args.sqlmap_timeout)
            if re.search(r"parameter ['\"]?.+['\"]? is vulnerable|appears to be injectable|is injectable", text, re.I):
                self.add_finding(Finding(
                    "Injection SQL confirmee par sqlmap", "critical", "Injection", "confirmed",
                    f"sqlmap signale le parametre {parameter} comme injectable.",
                    "Aucune extraction de donnees n'a ete executee.", "sqlmap", endpoint.url,
                ))

    def run_zap(self) -> None:
        requested = (self.args.active or self.args.zap) and not self.args.no_zap
        if not requested:
            self.coverage["ZAP / DOM XSS"] = "non demande"
            return
        zap = shutil.which("zaproxy") or shutil.which("zap.sh")
        if not zap:
            self.tools["zap"] = "missing"
            self.coverage["ZAP / DOM XSS"] = "ZAP absent"
            self.log("WARN", "ZAP absent. Installez-le avec: sudo apt install zaproxy")
            return
        plan_file = self.raw / "zap-plan.yaml"
        jobs: list[str] = []
        jobs.append(
            "  - type: spider\n"
            "    parameters:\n"
            "      context: Scanner Context\n"
            f"      maxDuration: {self.args.zap_spider_minutes}\n"
        )
        jobs.append("  - type: passiveScan-wait\n    parameters:\n      maxDuration: 5\n")
        if not self.args.no_zap_ajax:
            jobs.append(
                "  - type: spiderAjax\n"
                "    parameters:\n"
                "      context: Scanner Context\n"
                f"      url: {yaml_string(self.target)}\n"
                f"      maxDuration: {self.args.zap_ajax_minutes}\n"
                "      maxCrawlDepth: 5\n"
                "      numberOfBrowsers: 1\n"
                "      browserId: firefox-headless\n"
                "      inScopeOnly: true\n"
                "      logoutAvoidance: true\n"
            )
            jobs.append("  - type: passiveScan-wait\n    parameters:\n      maxDuration: 5\n")
        for source in self.openapi_sources:
            parameter = "apiUrl" if re.match(r"^https?://", source, re.I) else "apiFile"
            jobs.append(
                "  - type: openapi\n"
                "    parameters:\n"
                f"      {parameter}: {yaml_string(str(Path(source).resolve()) if parameter == 'apiFile' else source)}\n"
                "      context: Scanner Context\n"
                f"      targetUrl: {yaml_string(self.target)}\n"
            )
        for endpoint in sorted(self.graphql_endpoints):
            jobs.append(
                "  - type: graphql\n"
                "    parameters:\n"
                f"      endpoint: {yaml_string(endpoint)}\n"
                "      queryGenEnabled: true\n"
                "      maxQueryDepth: 3\n"
                "      maxArgsDepth: 3\n"
            )
        if self.args.active:
            jobs.append(
                "  - type: activeScan\n"
                "    parameters:\n"
                "      context: Scanner Context\n"
                f"      maxScanDurationInMins: {self.args.zap_active_minutes}\n"
                "      maxRuleDurationInMins: 2\n"
                "      defaultStrength: Medium\n"
                "      defaultThreshold: Low\n"
                "      delayInMs: 20\n"
                "      threadPerHost: 2\n"
                "      maxAlertsPerRule: 20\n"
                "      handleAntiCSRFTokens: true\n"
            )
        jobs.append(
            "  - type: report\n"
            "    parameters:\n"
            "      template: traditional-json\n"
            f"      reportDir: {yaml_string(str(self.raw.resolve()))}\n"
            "      reportFile: zap-report.json\n"
        )
        jobs.append(
            "  - type: report\n"
            "    parameters:\n"
            "      template: traditional-html\n"
            f"      reportDir: {yaml_string(str(self.raw.resolve()))}\n"
            "      reportFile: zap-report.html\n"
        )
        include_regex = re.escape(self.origin) + r".*"
        plan = (
            "env:\n"
            "  contexts:\n"
            "    - name: Scanner Context\n"
            "      urls:\n"
            f"        - {yaml_string(self.target)}\n"
            "      includePaths:\n"
            f"        - {yaml_string(include_regex)}\n"
            "jobs:\n" + "".join(jobs)
        )
        plan_file.write_text(plan, encoding="utf-8")
        self.run_tool("zap", [zap, "-cmd", "-autorun", str(plan_file)], self.args.zap_timeout)
        self.parse_zap_report(self.raw / "zap-report.json")
        ajax_status = "Ajax Spider + scan actif; DOM XSS si add-on Selenium/DOM XSS et navigateur disponibles" if not self.args.no_zap_ajax else "scan ZAP sans Ajax Spider"
        self.coverage["ZAP / DOM XSS"] = ajax_status

    def parse_zap_report(self, path: Path) -> None:
        if not path.exists():
            self.log("WARN", "Rapport JSON ZAP absent; consultez raw/zap-report.html et raw/zap.txt.")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            self.log("WARN", f"Rapport ZAP JSON illisible: {error}")
            return
        count = 0
        for site in data.get("site", []) if isinstance(data, dict) else []:
            for alert in site.get("alerts", []):
                risk = str(alert.get("riskdesc", alert.get("risk", "Informational"))).split()[0].lower()
                severity = {
                    "critical": "critical", "high": "high", "medium": "medium", "low": "low",
                    "informational": "info", "info": "info",
                }.get(risk, "info")
                instances = alert.get("instances", []) or []
                first = instances[0] if instances else {}
                evidence = str(first.get("evidence") or alert.get("evidence") or alert.get("desc") or "Alerte ZAP")
                url = str(first.get("uri") or first.get("url") or self.target)
                confidence_raw = str(alert.get("confidence", alert.get("confidencedesc", "medium"))).lower()
                confidence = "confirmed" if "high" in confidence_raw else "probable"
                self.add_finding(Finding(
                    str(alert.get("alert") or alert.get("name") or "Alerte ZAP"),
                    severity, "ZAP", confidence, strip_html(evidence)[:600],
                    strip_html(str(alert.get("solution") or alert.get("desc") or "Valider l'alerte dans ZAP."))[:800],
                    "ZAP", url,
                ))
                count += 1
        self.log("OK", f"Alertes ZAP importees dans le rapport principal: {count}.")

    # ------------------------------------------------------------------
    # Rapport et orchestration
    # ------------------------------------------------------------------

    def write_report(self) -> None:
        self.findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.title.lower()))
        endpoints = sorted(
            (asdict(item) for item in self.endpoints.values()),
            key=lambda item: (not item["confirmed"], item["url"], item["method"]),
        )
        summary = {
            severity: sum(1 for finding in self.findings if finding.severity == severity)
            for severity in SEVERITY_ORDER
        }
        limitations = []
        if not self.args.har:
            limitations.append("Aucun HAR principal fourni: les parcours dynamiques et authentifies sont moins couverts.")
        if not self.args.har_user_a or not self.args.har_user_b:
            limitations.append("Les controles d'acces inter-comptes necessitent deux HAR de comptes de test.")
        if not self.args.business_config:
            limitations.append("La logique metier propre a l'application necessite des scenarios configures.")
        if self.coverage.get("ZAP / DOM XSS") in {"non demande", "ZAP absent"}:
            limitations.append("Les XSS DOM et la navigation JavaScript profonde necessitent ZAP Ajax Spider et un navigateur.")
        limitations.append("Les constats probable/possible doivent etre confirmes manuellement avant toute conclusion.")
        report = {
            "scanner_version": VERSION,
            "target": self.target,
            "profile": self.profile,
            "mode": "active" if self.args.active else "passive",
            "duration_seconds": round(time.monotonic() - self.started, 2),
            "active_tests": self.active_tests,
            "tools": self.tools,
            "coverage": self.coverage,
            "summary": summary,
            "findings": [asdict(item) for item in self.findings],
            "endpoints": endpoints,
            "limitations": limitations,
        }
        (self.output / "report.json").write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        (self.output / "report.html").write_text(render_html(report), encoding="utf-8")
        target_dir = self.output.parent
        latest = target_dir / "latest-report.html"
        try:
            if latest.exists() or latest.is_symlink():
                latest.unlink()
            latest.symlink_to(self.output.name + "/report.html")
        except OSError:
            shutil.copy2(self.output / "report.html", latest)
        self.log("OK", f"Rapport genere: {self.output / 'report.html'}")

    def run(self) -> None:
        total = 13
        self.phase(1, total, "Validation de la cible")
        self.log("WARN", "Utilisez ce scanner uniquement sur une cible autorisee.")
        self.log("INFO", f"Cible: {self.target} | Mode: {'actif' if self.args.active else 'passif'}")
        self.phase(2, total, "Reconnaissance avec les outils Kali")
        if not self.args.no_tools:
            self.reconnaissance()
        else:
            self.coverage["Reconnaissance Kali"] = "ignoree (--no-tools)"
        self.phase(3, total, "Analyse HTTP, cookies, CORS et methodes")
        home = self.initial_http_analysis()
        self.phase(4, total, "Crawl HTML et identification de l'application")
        scripts, _forms = self.crawl(home)
        self.phase(5, total, "Analyse JavaScript, OpenAPI et GraphQL")
        self.analyse_javascript(scripts)
        self.import_openapi()
        self.probe_graphql()
        self.phase(6, total, "Import des HAR et analyse JWT")
        self.import_hars()
        self.phase(7, total, "Verification des routes sensibles")
        self.probe_sensitive_paths()
        self.phase(8, total, "Mutations actives GET, POST et JSON")
        self.active_mutations()
        self.phase(9, total, "Authentification, session et controles d'acces")
        self.auth_tests()
        self.access_control_tests()
        self.session_tests()
        self.phase(10, total, "Scenarios de logique metier")
        self.business_tests()
        self.phase(11, total, "Moteurs complementaires sqlmap et Nuclei")
        self.run_sqlmap()
        self.run_nuclei()
        self.phase(12, total, "ZAP Spider, Ajax Spider, DOM XSS et scan actif")
        self.run_zap()
        self.phase(13, total, "Generation du rapport consolide")
        self.write_report()
        self.log(
            "DONE",
            f"Termine en {time.monotonic() - self.started:.1f}s | Profil: {self.profile} | Findings: {len(self.findings)}",
        )


# ----------------------------------------------------------------------
# Fonctions utilitaires
# ----------------------------------------------------------------------


def normalize_url(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("La cible doit commencer par http:// ou https://")
    parts = urlsplit(url.strip())
    if not parts.hostname:
        raise ValueError("Nom d'hote absent")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path.rstrip("/") or "/", parts.query, ""))


def normalize_url_soft(url: str) -> str:
    try:
        return normalize_url(url) if url else ""
    except ValueError:
        return url


def encode_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname
    if not hostname:
        raise ValueError("URL sans hote")
    host = hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    userinfo = ""
    if parts.username:
        userinfo = quote(parts.username, safe="")
        if parts.password:
            userinfo += ":" + quote(parts.password, safe="")
        userinfo += "@"
    netloc = userinfo + host + (f":{parts.port}" if parts.port else "")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%/:?@!$'()*+,;[]-._~")
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def same_origin(base: str, candidate: str) -> bool:
    a, b = urlsplit(base), urlsplit(candidate)
    return (
        a.scheme.lower() == b.scheme.lower()
        and a.hostname == b.hostname
        and (a.port or default_port(a.scheme)) == (b.port or default_port(b.scheme))
    )


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def valid_route(route: str) -> bool:
    if not route or len(route) > 240 or any(
        token in route for token in ["\n", "\r", "}},", "console.log", "function(", "=>"]
    ):
        return False
    if route.startswith(("data:", "javascript:", "mailto:", "tel:")):
        return False
    return route.startswith(("/", "http://", "https://")) and " " not in route


def first_existing(paths: list[str]) -> str | None:
    return next((path for path in paths if Path(path).exists()), None)


def flatten_json_keys(value: Any, prefix: str = "") -> list[str]:
    keys: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            keys.append(name)
            keys.extend(flatten_json_keys(child, name))
    elif isinstance(value, list):
        for child in value[:3]:
            keys.extend(flatten_json_keys(child, prefix))
    return keys


def set_json_path(value: Any, path: str, replacement: Any) -> bool:
    parts = [part for part in path.split(".") if part]
    if not parts:
        return False
    current = value
    for part in parts[:-1]:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False
    if isinstance(current, dict) and parts[-1] in current:
        current[parts[-1]] = replacement
        return True
    return False


def schema_property_names(schema: Any, prefix: str = "") -> list[str]:
    if not isinstance(schema, dict):
        return []
    if "$ref" in schema:
        return []
    names: list[str] = []
    for key, child in schema.get("properties", {}).items():
        name = f"{prefix}.{key}" if prefix else str(key)
        names.append(name)
        names.extend(schema_property_names(child, name))
    return names


def substitute_path_parameters(path: str) -> str:
    return re.sub(r"\{[^{}]+\}", "1", path)


def unsafe_replay_url(url: str) -> bool:
    lower = url.lower()
    return any(word in lower for word in DANGEROUS_REPLAY_WORDS)


def is_sensitive_resource(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(re.search(rf"(?:^|[/_-]){re.escape(word)}(?:$|[/_.-])", path) for word in SENSITIVE_RESOURCE_WORDS)


def session_headers(requests: list[ReplayRequest]) -> dict[str, str]:
    for request in requests:
        auth = {key: value for key, value in request.headers.items() if key in AUTH_HEADER_NAMES}
        if auth:
            return auth
    return {}


def response_similarity(first: HttpResult, second: HttpResult) -> float:
    if first.status != second.status:
        return 0.0
    text_a = first.text[:20000]
    text_b = second.text[:20000]
    if not text_a and not text_b:
        return 1.0
    return SequenceMatcher(None, text_a, text_b).ratio()


def reflection_context(text: str, marker: str) -> str:
    index = text.find(marker)
    if index < 0:
        return "absent"
    before = text[max(0, index - 200):index].lower()
    after = text[index:index + 200].lower()
    if "<script" in before and "</script" in after:
        return "script"
    if re.search(r"on\w+\s*=\s*['\"][^'\"]*$", before):
        return "event-handler"
    if re.search(r"(?:href|src|style|value)\s*=\s*['\"][^'\"]*$", before):
        return "html-attribute"
    if "<" in before and ">" in after:
        return "html-text"
    return "texte"


def replace_placeholders(value: Any, username: str, password: str) -> Any:
    if isinstance(value, dict):
        return {key: replace_placeholders(child, username, password) for key, child in value.items()}
    if isinstance(value, list):
        return [replace_placeholders(child, username, password) for child in value]
    if isinstance(value, str):
        return value.replace("{username}", username).replace("{password}", password)
    return value


def strip_html(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", value)).strip()


def yaml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_html(report: dict[str, Any]) -> str:
    findings = report["findings"]
    endpoints = report["endpoints"]
    summary_cards = "".join(
        f'<div class="card"><strong>{report["summary"][severity]}</strong><span>{severity}</span></div>'
        for severity in ["critical", "high", "medium", "low", "info"]
    )
    finding_html = "".join(
        f"""
        <article class="finding {html.escape(item['severity'])}">
          <header><h3>{html.escape(item['title'])}</h3><span>{html.escape(item['severity'])}</span></header>
          <dl>
            <dt>Categorie</dt><dd>{html.escape(item['category'])}</dd>
            <dt>Confiance</dt><dd>{html.escape(item['confidence'])}</dd>
            <dt>Source</dt><dd>{html.escape(item['source'])}</dd>
            <dt>URL</dt><dd>{html.escape(item['url'])}</dd>
            <dt>Preuve</dt><dd><code>{html.escape(item['evidence'])}</code></dd>
            <dt>Interpretation</dt><dd>{html.escape(item['interpretation'])}</dd>
          </dl>
        </article>
        """ for item in findings
    ) or "<p>Aucun constat.</p>"
    endpoint_rows = "".join(
        f"<tr><td>{html.escape(item['method'])}</td><td>{html.escape(item['url'])}</td>"
        f"<td>{item['status'] if item['status'] is not None else '-'}</td>"
        f"<td>{'oui' if item['confirmed'] else 'candidat'}</td><td>{html.escape(item['source'])}</td>"
        f"<td>{html.escape(', '.join(item['parameters']))}</td></tr>"
        for item in endpoints
    )
    tool_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{html.escape(status)}</td></tr>"
        for name, status in report["tools"].items()
    )
    coverage_rows = "".join(
        f"<tr><td>{html.escape(name)}</td><td>{html.escape(status)}</td></tr>"
        for name, status in report["coverage"].items()
    )
    limits = "".join(f"<li>{html.escape(item)}</li>" for item in report["limitations"])
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport DevSecOps</title>
<style>
body{{font-family:Arial,sans-serif;margin:0;background:#f4f6f8;color:#17202a}}main{{max-width:1200px;margin:auto;padding:28px}}h1,h2{{margin-top:0}}.meta,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}}.card,.panel,.finding{{background:white;border-radius:10px;padding:16px;box-shadow:0 1px 4px #0002}}.card strong{{display:block;font-size:28px}}.card span{{text-transform:uppercase}}table{{width:100%;border-collapse:collapse;background:white;margin-bottom:22px}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}.finding{{margin:14px 0;border-left:6px solid #999}}.finding.critical{{border-color:#7b0015}}.finding.high{{border-color:#c0392b}}.finding.medium{{border-color:#e67e22}}.finding.low{{border-color:#f1c40f}}.finding.info{{border-color:#3498db}}.finding header{{display:flex;justify-content:space-between;gap:12px}}dl{{display:grid;grid-template-columns:140px 1fr;gap:7px}}dt{{font-weight:bold}}dd{{margin:0}}code{{white-space:pre-wrap;word-break:break-word}}.warning{{padding:14px;background:#fff3cd;border:1px solid #ffe69c;border-radius:8px}}@media(max-width:700px){{dl{{grid-template-columns:1fr}}table{{font-size:12px}}}}
</style></head><body><main>
<h1>Rapport DevSecOps Scanner {VERSION}</h1>
<div class="warning">Ce rapport automatise la detection d'indices. Les constats probables et possibles doivent etre valides manuellement.</div>
<div class="meta"><div class="panel"><b>Cible</b><br>{html.escape(report['target'])}</div><div class="panel"><b>Mode</b><br>{html.escape(report['mode'])}</div><div class="panel"><b>Profil</b><br>{html.escape(report['profile'])}</div><div class="panel"><b>Tests actifs</b><br>{report['active_tests']}</div><div class="panel"><b>Duree</b><br>{report['duration_seconds']} s</div></div>
<h2>Resume</h2><div class="grid">{summary_cards}</div>
<h2>Couverture</h2><table><thead><tr><th>Module</th><th>Etat</th></tr></thead><tbody>{coverage_rows}</tbody></table>
<h2>Outils</h2><table><thead><tr><th>Outil</th><th>Etat</th></tr></thead><tbody>{tool_rows}</tbody></table>
<h2>Constats</h2>{finding_html}
<h2>Endpoints</h2><table><thead><tr><th>Methode</th><th>URL</th><th>HTTP</th><th>Etat</th><th>Source</th><th>Parametres</th></tr></thead><tbody>{endpoint_rows}</tbody></table>
<h2>Limites restantes</h2><ul>{limits}</ul>
</main></body></html>"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scanner web pedagogique consolide")
    parser.add_argument("target", help="URL complete de la cible")
    parser.add_argument("--active", action="store_true", help="Active les mutations et le scan actif ZAP")
    parser.add_argument("--active-post", action="store_true", help="Autorise les mutations POST/PUT/PATCH issues du HAR")
    parser.add_argument("--har", help="HAR principal pour decouvrir les requetes dynamiques")
    parser.add_argument("--har-user-a", help="HAR authentifie du compte A")
    parser.add_argument("--har-user-b", help="HAR authentifie du compte B")
    parser.add_argument("--use-har-auth", action="store_true", help="Autorise la reutilisation des cookies/tokens des HAR")
    parser.add_argument("--access-tests", action="store_true", help="Compare les acces comptes A/B/anonyme")
    parser.add_argument("--session-tests", action="store_true", help="Teste une session apres une requete de logout du HAR A")
    parser.add_argument("--auth-config", help="JSON de test login et anti-automatisation")
    parser.add_argument("--business-config", help="JSON de scenarios de logique metier")
    parser.add_argument("--openapi", help="URL ou fichier JSON OpenAPI/Swagger")
    parser.add_argument("--graphql-url", help="URL de l'endpoint GraphQL")
    parser.add_argument("--graphql-introspection", action="store_true", help="Teste l'introspection GraphQL")
    parser.add_argument("--zap", action="store_true", help="Lance ZAP meme en mode passif")
    parser.add_argument("--no-zap", action="store_true", help="Desactive ZAP, y compris en mode actif")
    parser.add_argument("--no-zap-ajax", action="store_true", help="Desactive Ajax Spider")
    parser.add_argument("--nuclei", action="store_true", help="Lance Nuclei en complement")
    parser.add_argument("--nuclei-timeout", type=int, default=120)
    parser.add_argument("--sqlmap", action="store_true", help="Lance sqlmap sur deux parametres GET maximum")
    parser.add_argument("--sqlmap-timeout", type=int, default=180)
    parser.add_argument("--profile", choices=["auto", "global", "juice-shop"], default="auto")
    parser.add_argument("--output", default="results")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--max-pages", type=int, default=30)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-scripts", type=int, default=12)
    parser.add_argument("--max-active", type=int, default=15)
    parser.add_argument("--max-access-tests", type=int, default=10)
    parser.add_argument("--max-body", type=int, default=2_000_000)
    parser.add_argument("--zap-spider-minutes", type=int, default=2)
    parser.add_argument("--zap-ajax-minutes", type=int, default=4)
    parser.add_argument("--zap-active-minutes", type=int, default=10)
    parser.add_argument("--zap-timeout", type=int, default=1200)
    parser.add_argument("--no-tools", action="store_true", help="Ignore WhatWeb, Nmap, Gobuster et Nikto")
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        Scanner(args).run()
        return 0
    except KeyboardInterrupt:
        print("\nScan interrompu.", file=sys.stderr)
        return 130
    except Exception as error:
        print(f"[ERREUR] {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
