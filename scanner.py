#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, Request, build_opener

VERSION = "2.0.0"
USER_AGENT = f"DevSecOps-Scanner/{VERSION}"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SQL_ERROR_PATTERNS = re.compile(
    r"SQL syntax|SQLITE_ERROR|SQLSTATE|Sequelize|mysql_fetch|mysqli?|PostgreSQL|pg_query|ORA-\d+|unterminated quoted string|database error",
    re.IGNORECASE,
)
SENSITIVE_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/api", "/api/", "/rest", "/rest/",
    "/graphql", "/swagger.json", "/openapi.json", "/api-docs", "/admin", "/administrator", "/login",
    "/debug", "/metrics", "/health", "/status", "/actuator", "/actuator/health", "/actuator/env",
    "/files", "/ftp", "/uploads", "/backup", "/backups", "/.git/HEAD", "/.env", "/src",
]
JUICE_SHOP_PATHS = [
    "/ftp/", "/ftp/package.json.bak", "/metrics", "/api/Challenges", "/rest/admin/application-version",
    "/rest/products/search?q=apple", "/rest/user/login",
]
DANGEROUS_REPLAY_WORDS = {
    "delete", "remove", "checkout", "payment", "purchase", "order", "upload", "reset-password",
    "change-password", "transfer", "admin", "logout",
}


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
            }
        if tag in {"input", "textarea", "select", "button"} and self._form is not None and data.get("name"):
            self._form["parameters"].append(data["name"])
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
        self.tools: dict[str, str] = {}
        self.active_tests = 0
        self.profile = "global"
        self.page_title = ""
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
        key = (finding.title.lower(), finding.url, finding.evidence[:160])
        existing = {(item.title.lower(), item.url, item.evidence[:160]) for item in self.findings}
        if key not in existing:
            self.findings.append(finding)
            self.log("FINDING", f"{finding.severity.upper()} - {finding.title}")

    def add_endpoint(self, method: str, url: str, source: str, status: int | None = None, confirmed: bool = False) -> Endpoint:
        absolute = normalize_url(urljoin(self.target, url))
        if not same_origin(self.target, absolute):
            return Endpoint(method, absolute, source, status, False)
        key = (method.upper(), absolute)
        endpoint = self.endpoints.get(key)
        if endpoint is None:
            params = sorted({name for name, _ in parse_qsl(urlsplit(absolute).query, keep_blank_values=True)})
            endpoint = Endpoint(method.upper(), absolute, source, status, confirmed, params)
            self.endpoints[key] = endpoint
        else:
            endpoint.confirmed = endpoint.confirmed or confirmed
            endpoint.status = endpoint.status if endpoint.status is not None else status
            endpoint.parameters = sorted(set(endpoint.parameters) | {name for name, _ in parse_qsl(urlsplit(absolute).query, keep_blank_values=True)})
        return endpoint

    def request(self, url: str, method: str = "GET", data: bytes | None = None, headers: dict[str, str] | None = None,
                follow_redirects: bool = True) -> HttpResult:
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
                return HttpResult(response.geturl(), response.status, {k.lower(): v for k, v in response.headers.items()}, body,
                                  time.monotonic() - started)
        except HTTPError as error:
            body = error.read(self.args.max_body)
            return HttpResult(encoded, error.code, {k.lower(): v for k, v in error.headers.items()}, body,
                              time.monotonic() - started, str(error))
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
            text = (error.stdout or "") + "\nTIMEOUT"
            output_path.write_text(str(text), encoding="utf-8", errors="replace")
            self.tools[name] = "timeout"
            self.log("WARN", f"{name} interrompu apres {timeout}s.")
            return str(text)

    def reconnaissance(self) -> None:
        self.run_tool("whatweb", ["whatweb", "-a", "1", self.target], 120)
        self.run_tool("nmap", ["nmap", "-Pn", "-sV", "-p", str(self.port), self.host], 180)
        wordlist = first_existing([
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ])
        if wordlist:
            random_url = urljoin(self.target + "/", f"not-found-{uuid.uuid4().hex}")
            baseline = self.request(random_url)
            command = ["gobuster", "dir", "-u", self.target, "-w", wordlist, "-t", "5", "--timeout", f"{self.args.timeout}s", "-q"]
            if baseline.body:
                command.extend(["--exclude-length", str(len(baseline.body))])
            gobuster_output = self.run_tool("gobuster", command, 300)
            self.parse_gobuster(gobuster_output)
        else:
            self.tools["gobuster"] = "no-wordlist"
            self.log("WARN", "Gobuster ignore: aucune wordlist commune trouvee.")
        nikto_output = self.run_tool("nikto", ["nikto", "-h", self.target, "-nointeractive", "-maxtime", "5m"], 360)
        self.parse_nikto(nikto_output)

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
                self.add_finding(Finding("Header de securite manquant", "low", "Security Misconfiguration", "confirmed",
                                         clean[:400], "Nikto signale une politique HTTP absente ou insuffisante.", "Nikto", self.target))
            elif "might be interesting" in lower:
                self.add_finding(Finding("Ressource potentiellement sensible", "low", "Content Discovery", "possible",
                                         clean[:400], "La ressource doit etre analysee manuellement.", "Nikto", self.target))

    def initial_http_analysis(self) -> HttpResult:
        result = self.request(self.target)
        if result.status == 0:
            raise RuntimeError(f"Cible inaccessible: {result.error}")
        (self.raw / "home.html").write_bytes(result.body)
        (self.raw / "headers.json").write_text(json.dumps(result.headers, indent=2, ensure_ascii=False), encoding="utf-8")
        self.add_endpoint("GET", self.target, "initial", result.status, True)
        required = {
            "content-security-policy": ("Content-Security-Policy absent", "low", "Peut augmenter l'impact de certaines injections cote navigateur."),
            "x-content-type-options": ("X-Content-Type-Options absent", "low", "Le navigateur peut interpreter un contenu avec un type inattendu."),
            "referrer-policy": ("Referrer-Policy absent", "low", "Des informations d'URL peuvent etre transmises a d'autres sites."),
            "permissions-policy": ("Permissions-Policy absent", "info", "Les fonctions du navigateur ne sont pas explicitement restreintes."),
        }
        for header, (title, severity, interpretation) in required.items():
            if header not in result.headers:
                self.add_finding(Finding(title, severity, "Security Misconfiguration", "confirmed",
                                         f"Header {header} absent.", interpretation, "HTTP", self.target))
        if self.target.startswith("https://") and "strict-transport-security" not in result.headers:
            self.add_finding(Finding("Strict-Transport-Security absent", "low", "Cryptographic Issues", "confirmed",
                                     "Header HSTS absent sur une cible HTTPS.", "Le navigateur n'est pas force a reutiliser HTTPS.", "HTTP", self.target))
        if result.headers.get("server"):
            self.add_finding(Finding("Technologie serveur exposee", "info", "Information Disclosure", "confirmed",
                                     f"Server: {result.headers['server']}", "Cette information facilite la reconnaissance.", "HTTP", self.target))
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
                self.add_finding(Finding("Cookie insuffisamment protege", "medium", "Session Management", "confirmed",
                                         f"Cookie {cookie.name}: attributs absents {', '.join(missing)}.",
                                         "Les protections du cookie de session doivent etre verifiees.", "HTTP", self.target))
        return result

    def crawl(self, home: HttpResult) -> tuple[list[str], list[dict[str, Any]]]:
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
                endpoint = self.add_endpoint(form["method"], action, "html-form", confirmed=True)
                endpoint.parameters = sorted(set(endpoint.parameters) | set(form["parameters"]))
            if depth < self.args.depth:
                for link in parser.links:
                    next_url = strip_fragment(urljoin(url, link))
                    if same_origin(self.target, next_url) and next_url not in visited:
                        queue.append((next_url, depth + 1))
        self.log("OK", f"Crawl: {len(visited)} page(s), {len(scripts)} script(s), {len(forms)} formulaire(s).")
        self.fingerprint(all_text)
        return sorted(scripts), forms

    def fingerprint(self, text: str) -> None:
        lower = text.lower()
        if "juice shop" in lower or "owasp juice" in lower or "juiceshop" in lower:
            self.profile = "juice-shop"
        elif "universalTouchGamepad".lower() in lower or "selkieslogoalt" in lower or "selkies" in lower:
            self.profile = "selkies"
        elif "wordpress" in lower or "wp-content" in lower:
            self.profile = "wordpress"
        if self.args.profile != "auto":
            self.profile = self.args.profile
        if self.profile == "selkies":
            self.add_finding(Finding("La cible ne semble pas etre OWASP Juice Shop", "info", "Target Identification", "confirmed",
                                     "Empreinte Selkies/streaming detectee (universalTouchGamepad ou selkies).",
                                     "Le port analyse semble exposer une autre application. Verifiez le conteneur et le port de Juice Shop.",
                                     "Fingerprint", self.target))
            self.log("WARN", "Empreinte Selkies detectee: cette cible ne ressemble pas a OWASP Juice Shop.")
        else:
            self.log("INFO", f"Profil applicatif detecte: {self.profile}.")

    def analyse_javascript(self, scripts: list[str]) -> None:
        patterns = [
            (re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]", re.I), "GET", "javascript-fetch"),
            (re.compile(r"axios\.(get|post|put|delete|patch)\(\s*['\"]([^'\"]+)['\"]", re.I), None, "javascript-axios"),
            (re.compile(r"\.open\(\s*['\"](GET|POST|PUT|DELETE|PATCH)['\"]\s*,\s*['\"]([^'\"]+)['\"]", re.I), None, "javascript-xhr"),
            (re.compile(r"['\"]((?:https?://[^'\"]+)?/(?:api|rest|auth|admin|graphql|metrics|ftp|files)(?:/[A-Za-z0-9_.{}:%-]+)*(?:\?[A-Za-z0-9_=&%{}.-]*)?)['\"]", re.I), "UNKNOWN", "javascript-route"),
        ]
        combined = ""
        for index, script_url in enumerate(scripts[: self.args.max_scripts], start=1):
            result = self.request(script_url)
            if result.status != 200 or not result.body:
                continue
            path = self.raw / f"script-{index}.js"
            path.write_bytes(result.body)
            content = result.text
            combined += "\n" + content[:500000]
            if "localStorage" in content:
                self.add_finding(Finding("Stockage local utilise", "info", "Client-side Analysis", "possible",
                                         f"localStorage trouve dans {script_url}", "Verifier si des tokens ou donnees sensibles y sont stockes.",
                                         "JavaScript", script_url))
            if re.search(r"sourceMappingURL=", content):
                self.add_finding(Finding("Source map referencee", "low", "Information Disclosure", "possible",
                                         f"Source map referencee dans {script_url}", "Une source map accessible peut exposer le code source original.",
                                         "JavaScript", script_url))
            for pattern, fixed_method, source in patterns:
                for match in pattern.finditer(content):
                    if source == "javascript-fetch":
                        method, route = fixed_method or "GET", match.group(1)
                    else:
                        if source in {"javascript-axios", "javascript-xhr"}:
                            method, route = match.group(1).upper(), match.group(2)
                        else:
                            method, route = fixed_method or "UNKNOWN", match.group(1)
                    if valid_route(route):
                        self.add_endpoint(method, route, source)
        if self.profile == "global" and combined:
            self.fingerprint(combined)
        self.log("OK", f"JavaScript: {min(len(scripts), self.args.max_scripts)} fichier(s) examine(s).")

    def import_har(self) -> None:
        if not self.args.har:
            return
        path = Path(self.args.har)
        if not path.exists():
            self.log("WARN", f"HAR introuvable: {path}")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            self.log("WARN", f"HAR illisible: {error}")
            return
        count = 0
        for entry in data.get("log", {}).get("entries", []):
            request_data = entry.get("request", {})
            url = request_data.get("url", "")
            if not url or not same_origin(self.target, url):
                continue
            method = request_data.get("method", "GET").upper()
            endpoint = self.add_endpoint(method, url, "har", confirmed=True)
            endpoint.parameters = sorted(set(endpoint.parameters) | {item.get("name", "") for item in request_data.get("queryString", []) if item.get("name")})
            post_data = request_data.get("postData", {})
            for item in post_data.get("params", []) or []:
                if item.get("name"):
                    endpoint.parameters.append(item["name"])
            text = post_data.get("text", "")
            if text and "json" in post_data.get("mimeType", "").lower():
                try:
                    payload = json.loads(text)
                    endpoint.parameters.extend(flatten_json_keys(payload))
                except json.JSONDecodeError:
                    pass
            for header in request_data.get("headers", []):
                if header.get("name", "").lower() == "authorization" and header.get("value", "").lower().startswith("bearer "):
                    self.inspect_jwt(header["value"].split(None, 1)[1], url)
            endpoint.parameters = sorted(set(endpoint.parameters))
            count += 1
        self.log("OK", f"HAR: {count} requete(s) de la meme origine importee(s).")

    def inspect_jwt(self, token: str, url: str) -> None:
        parts = token.split(".")
        if len(parts) != 3:
            return
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4)))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        except Exception:
            return
        if str(header.get("alg", "")).lower() == "none":
            self.add_finding(Finding("JWT utilisant alg=none", "critical", "Broken Authentication", "confirmed",
                                     "Le header JWT declare alg=none.", "Le token peut ne pas etre signe.", "HAR/JWT", url))
        if "exp" not in payload:
            self.add_finding(Finding("JWT sans expiration", "medium", "Broken Authentication", "confirmed",
                                     "Claim exp absent.", "Un token sans expiration peut rester valide trop longtemps.", "HAR/JWT", url))
        sensitive = [key for key in payload if re.search(r"password|secret|card|token", key, re.I)]
        if sensitive:
            self.add_finding(Finding("Donnees potentiellement sensibles dans un JWT", "medium", "Sensitive Data Exposure", "possible",
                                     f"Claims sensibles: {', '.join(sensitive)}", "Le payload JWT est lisible par le client.", "HAR/JWT", url))

    def probe_sensitive_paths(self) -> None:
        random_result = self.request(urljoin(self.target + "/", f"missing-{uuid.uuid4().hex}"), follow_redirects=False)
        paths = list(SENSITIVE_PATHS)
        if self.profile == "juice-shop":
            paths.extend(JUICE_SHOP_PATHS)
        confirmed = 0
        for path in dict.fromkeys(paths):
            result = self.request(urljoin(self.target + "/", path.lstrip("/")), follow_redirects=False)
            same_fallback = result.status == random_result.status and result.signature == random_result.signature
            exists = result.status in {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403} and not same_fallback
            self.add_endpoint("GET", path, "sensitive-probe", result.status, exists)
            if not exists:
                continue
            confirmed += 1
            lower_path = path.lower()
            if lower_path in {"/.env", "/.git/head"} and result.status == 200:
                self.add_finding(Finding("Fichier de configuration sensible expose", "critical", "Sensitive Data Exposure", "confirmed",
                                         f"{path} retourne HTTP 200.", "Des secrets ou le code source peuvent etre exposes.", "Active probe", result.url))
            elif "package.json.bak" in lower_path and result.status == 200:
                self.add_finding(Finding("Sauvegarde de dependances exposee", "high", "Sensitive Data Exposure", "confirmed",
                                         f"{path} retourne HTTP 200.", "Le fichier peut exposer versions, dependances et informations internes.",
                                         "Juice Shop profile", result.url))
            elif lower_path in {"/metrics", "/actuator/env"} and result.status == 200:
                self.add_finding(Finding("Endpoint de diagnostic expose", "medium", "Security Misconfiguration", "confirmed",
                                         f"{path} retourne HTTP 200.", "Des informations internes ou metriques sont accessibles.", "Active probe", result.url))
            elif lower_path.startswith("/ftp") and result.status in {200, 301}:
                self.add_finding(Finding("Repertoire de fichiers accessible", "medium", "Sensitive Data Exposure", "confirmed",
                                         f"{path} retourne HTTP {result.status}.", "Verifier les documents et sauvegardes accessibles.", "Active probe", result.url))
        self.log("OK", f"Routes sensibles: {len(paths)} testee(s), {confirmed} distincte(s) detectee(s).")

    def active_mutations(self) -> None:
        if not self.args.active:
            return
        candidates = [endpoint for endpoint in self.endpoints.values() if endpoint.method in {"GET", "UNKNOWN"} and endpoint.parameters]
        self.log("INFO", f"Mutations actives: {len(candidates[: self.args.max_active])} endpoint(s) parametre(s).")
        for endpoint in candidates[: self.args.max_active]:
            parts = urlsplit(endpoint.url)
            original = dict(parse_qsl(parts.query, keep_blank_values=True))
            for name in endpoint.parameters[:3]:
                if name not in original:
                    continue
                baseline = self.request(endpoint.url, follow_redirects=False)
                marker = f"WSS_{uuid.uuid4().hex[:8]}"
                self.active_tests += 1
                reflected = self.mutated_get(parts, original, name, marker)
                if marker in reflected.text:
                    self.add_finding(Finding("Entree utilisateur reflechie", "medium", "XSS", "probable",
                                             f"Le marqueur {marker} est renvoye par le parametre {name}.",
                                             "La reflexion doit etre validee dans son contexte HTML/JavaScript; elle ne confirme pas seule une XSS.",
                                             "Active mutation", endpoint.url))
                self.active_tests += 1
                quoted = self.mutated_get(parts, original, name, original.get(name, "") + "'")
                if SQL_ERROR_PATTERNS.search(quoted.text) and not SQL_ERROR_PATTERNS.search(baseline.text):
                    self.add_finding(Finding("Erreur SQL declenchee par une entree", "high", "Injection", "probable",
                                             f"Une erreur SQL apparait apres mutation du parametre {name}.",
                                             "Une injection SQL est possible et doit etre confirmee par un test cible.", "Active mutation", endpoint.url))
                if baseline.status < 500 <= quoted.status:
                    self.add_finding(Finding("Erreur serveur provoquee par une entree", "medium", "Improper Input Validation", "confirmed",
                                             f"Le parametre {name} fait passer la reponse de HTTP {baseline.status} a {quoted.status}.",
                                             "La validation ou la gestion d'erreur est insuffisante.", "Active mutation", endpoint.url))
                if re.search(r"url|uri|redirect|return|next|continue|destination", name, re.I):
                    self.active_tests += 1
                    redirect = self.mutated_get(parts, original, name, "https://scanner.invalid/", follow_redirects=False)
                    location = redirect.headers.get("location", "")
                    if "scanner.invalid" in location:
                        self.add_finding(Finding("Redirection externe non validee", "high", "Unvalidated Redirects", "confirmed",
                                                 f"Location: {location}", "Un attaquant peut rediriger un utilisateur vers un domaine externe.",
                                                 "Active mutation", endpoint.url))

    def mutated_get(self, parts, original: dict[str, str], name: str, value: str, follow_redirects: bool = False) -> HttpResult:  # noqa: ANN001
        query = dict(original)
        query[name] = value
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), ""))
        return self.request(url, follow_redirects=follow_redirects)

    def run_nuclei(self) -> None:
        if not self.args.active:
            return
        output = self.run_tool("nuclei", ["nuclei", "-u", self.target, "-jsonl", "-severity", "info,low,medium,high,critical", "-rl", "5", "-silent"], 600)
        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info", {})
            severity = str(info.get("severity", "info")).lower()
            self.add_finding(Finding(str(info.get("name", item.get("template-id", "Alerte Nuclei"))), severity if severity in SEVERITY_ORDER else "info",
                                     "Nuclei", "confirmed", item.get("matched-at", item.get("host", "Detection Nuclei")),
                                     "Detection issue d'un template Nuclei.", "Nuclei", item.get("matched-at", self.target)))

    def run_sqlmap(self) -> None:
        if not self.args.active or shutil.which("sqlmap") is None:
            if self.args.active:
                self.tools["sqlmap"] = "missing"
                self.log("WARN", "sqlmap absent, confirmation SQLi ignoree.")
            return
        targets = [endpoint for endpoint in self.endpoints.values() if endpoint.method in {"GET", "UNKNOWN"} and endpoint.parameters]
        if self.profile == "juice-shop":
            login_url = urljoin(self.target + "/", "rest/user/login")
            command = [
                "sqlmap", "-u", login_url, "--method", "POST",
                "--data", '{"email":"test@example.com","password":"test"}',
                "--headers", "Content-Type: application/json", "-p", "email", "--batch", "--level", "2", "--risk", "1",
                "--threads", "1", "--timeout", str(self.args.timeout), "--retries", "0", "--disable-coloring",
                "--output-dir", str(self.raw / "sqlmap-login"),
            ]
            text = self.run_tool("sqlmap-login", command, 600)
            self.parse_sqlmap(text, login_url, "email")
        for index, endpoint in enumerate(targets[:2], start=1):
            parameter = endpoint.parameters[0]
            command = [
                "sqlmap", "-u", endpoint.url, "-p", parameter, "--batch", "--level", "1", "--risk", "1", "--smart",
                "--threads", "1", "--timeout", str(self.args.timeout), "--retries", "0", "--disable-coloring",
                "--output-dir", str(self.raw / f"sqlmap-{index}"),
            ]
            text = self.run_tool(f"sqlmap-{index}", command, 480)
            self.parse_sqlmap(text, endpoint.url, parameter)

    def parse_sqlmap(self, text: str, url: str, parameter: str) -> None:
        if re.search(r"parameter ['\"]?.+['\"]? is vulnerable|appears to be injectable|is injectable", text, re.I):
            self.add_finding(Finding("Injection SQL confirmee par sqlmap", "critical", "Injection", "confirmed",
                                     f"sqlmap signale le parametre {parameter} comme injectable.",
                                     "Le parametre doit etre corrige rapidement. Aucun dump de donnees n'a ete execute.", "sqlmap", url))

    def run_zap(self) -> None:
        if not self.args.active and not self.args.zap:
            return
        zap = shutil.which("zaproxy") or shutil.which("zap.sh")
        if not zap:
            self.tools["zap"] = "missing"
            self.log("WARN", "ZAP absent. Installez-le avec: sudo apt install zaproxy")
            return
        report_file = self.raw / "zap-report.html"
        plan_file = self.raw / "zap-plan.yaml"
        active_job = "" if not self.args.active else """
  - type: activeScan
    parameters:
      context: Scanner Context
      maxScanDurationInMins: 10
      maxRuleDurationInMins: 2
"""
        plan = f"""env:
  contexts:
    - name: Scanner Context
      urls:
        - {self.target}
jobs:
  - type: spider
    parameters:
      context: Scanner Context
      maxDuration: 2
  - type: spiderAjax
    parameters:
      context: Scanner Context
      maxDuration: 3
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
{active_job}  - type: report
    parameters:
      template: traditional-html
      reportDir: {self.raw.resolve()}
      reportFile: {report_file.name}
"""
        plan_file.write_text(plan, encoding="utf-8")
        self.run_tool("zap", [zap, "-cmd", "-autorun", str(plan_file)], 1200)

    def write_report(self) -> None:
        self.findings.sort(key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.title.lower()))
        endpoints = sorted((asdict(item) for item in self.endpoints.values()), key=lambda item: (not item["confirmed"], item["url"]))
        summary = {severity: sum(1 for finding in self.findings if finding.severity == severity) for severity in SEVERITY_ORDER}
        report = {
            "scanner_version": VERSION,
            "target": self.target,
            "profile": self.profile,
            "mode": "active" if self.args.active else "passive",
            "duration_seconds": round(time.monotonic() - self.started, 2),
            "active_tests": self.active_tests,
            "tools": self.tools,
            "summary": summary,
            "findings": [asdict(item) for item in self.findings],
            "endpoints": endpoints,
            "limitations": [
                "Un scanner automatique ne couvre pas toutes les failles de logique metier.",
                "Les XSS DOM necessitent un navigateur ou ZAP Ajax Spider pour etre confirmees.",
                "Les controles d'acces necessitent souvent plusieurs comptes et des donnees dont la propriete est connue.",
                "Un mode actif sans HAR ni ZAP dispose de moins de parametres a tester.",
            ],
        }
        (self.output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
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
        total = 9
        self.phase(1, total, "Validation de la cible")
        self.log("WARN", "Utilisez ce scanner uniquement sur une cible autorisee.")
        self.log("INFO", f"Cible: {self.target} | Mode: {'actif' if self.args.active else 'passif'}")
        self.phase(2, total, "Reconnaissance avec les outils Kali")
        if not self.args.no_tools:
            self.reconnaissance()
        self.phase(3, total, "Analyse HTTP initiale")
        home = self.initial_http_analysis()
        self.phase(4, total, "Crawl HTML et identification de l'application")
        scripts, _forms = self.crawl(home)
        self.phase(5, total, "Analyse JavaScript et import HAR")
        self.analyse_javascript(scripts)
        self.import_har()
        self.phase(6, total, "Verification des routes sensibles")
        self.probe_sensitive_paths()
        self.phase(7, total, "Tests actifs limites")
        if self.args.active:
            self.active_mutations()
            self.run_nuclei()
            self.run_sqlmap()
        else:
            self.log("INFO", "Mode passif: mutations, Nuclei et sqlmap ignores.")
        self.phase(8, total, "Analyse ZAP")
        self.run_zap()
        self.phase(9, total, "Generation du rapport")
        self.write_report()
        self.log("DONE", f"Termine en {time.monotonic() - self.started:.1f}s | Profil: {self.profile} | Findings: {len(self.findings)}")


def normalize_url(url: str) -> str:
    if not re.match(r"^https?://", url, re.I):
        raise ValueError("La cible doit commencer par http:// ou https://")
    parts = urlsplit(url.strip())
    if not parts.hostname:
        raise ValueError("Nom d'hote absent")
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc, path.rstrip("/") or "/", parts.query, ""))


def encode_url(url: str) -> str:
    parts = urlsplit(url)
    hostname = parts.hostname
    if not hostname:
        raise ValueError("URL sans hote")
    host = hostname.encode("idna").decode("ascii")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host + (f":{parts.port}" if parts.port else "")
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%/:?@!$'()*+,;[]-._~")
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def same_origin(base: str, candidate: str) -> bool:
    a, b = urlsplit(base), urlsplit(candidate)
    return a.scheme.lower() == b.scheme.lower() and a.hostname == b.hostname and (a.port or default_port(a.scheme)) == (b.port or default_port(b.scheme))


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def strip_fragment(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))


def valid_route(route: str) -> bool:
    if not route or len(route) > 240 or any(token in route for token in ["\n", "\r", "}},", "console.log", "function("]):
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
        f"<tr><td>{html.escape(item['method'])}</td><td>{html.escape(item['url'])}</td><td>{item['status'] if item['status'] is not None else '-'}</td><td>{'oui' if item['confirmed'] else 'candidat'}</td><td>{html.escape(item['source'])}</td><td>{html.escape(', '.join(item['parameters']))}</td></tr>"
        for item in endpoints
    )
    tool_rows = "".join(f"<tr><td>{html.escape(name)}</td><td>{html.escape(status)}</td></tr>" for name, status in report["tools"].items())
    limits = "".join(f"<li>{html.escape(item)}</li>" for item in report["limitations"])
    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport DevSecOps</title>
<style>
body{{font-family:Arial,sans-serif;margin:0;background:#f4f6f8;color:#17202a}}main{{max-width:1200px;margin:auto;padding:28px}}h1,h2{{margin-top:0}}.meta,.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}}.card,.panel,.finding{{background:white;border-radius:10px;padding:16px;box-shadow:0 1px 4px #0002}}.card strong{{display:block;font-size:28px}}.card span{{text-transform:uppercase}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:10px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top}}.finding{{margin:14px 0;border-left:6px solid #999}}.finding.critical{{border-color:#7b0015}}.finding.high{{border-color:#c0392b}}.finding.medium{{border-color:#e67e22}}.finding.low{{border-color:#f1c40f}}.finding.info{{border-color:#3498db}}.finding header{{display:flex;justify-content:space-between;gap:12px}}dl{{display:grid;grid-template-columns:140px 1fr;gap:7px}}dt{{font-weight:bold}}dd{{margin:0}}code{{white-space:pre-wrap;word-break:break-word}}.warning{{padding:14px;background:#fff3cd;border:1px solid #ffe69c;border-radius:8px}}@media(max-width:700px){{dl{{grid-template-columns:1fr}}table{{font-size:12px}}}}
</style></head><body><main>
<h1>Rapport DevSecOps Scanner {VERSION}</h1>
<div class="warning">Ce rapport automatise la detection d'indices. Les constats probables et possibles doivent etre valides manuellement.</div>
<div class="meta"><div class="panel"><b>Cible</b><br>{html.escape(report['target'])}</div><div class="panel"><b>Mode</b><br>{html.escape(report['mode'])}</div><div class="panel"><b>Profil</b><br>{html.escape(report['profile'])}</div><div class="panel"><b>Tests actifs</b><br>{report['active_tests']}</div><div class="panel"><b>Duree</b><br>{report['duration_seconds']} s</div></div>
<h2>Resume</h2><div class="grid">{summary_cards}</div>
<h2>Outils</h2><table><thead><tr><th>Outil</th><th>Etat</th></tr></thead><tbody>{tool_rows}</tbody></table>
<h2>Constats</h2>{finding_html}
<h2>Endpoints</h2><table><thead><tr><th>Methode</th><th>URL</th><th>HTTP</th><th>Etat</th><th>Source</th><th>Parametres</th></tr></thead><tbody>{endpoint_rows}</tbody></table>
<h2>Limites</h2><ul>{limits}</ul>
</main></body></html>"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scanner web pedagogique simplifie")
    parser.add_argument("target", help="URL complete de la cible")
    parser.add_argument("--active", action="store_true", help="Active les mutations, Nuclei, sqlmap et ZAP actif")
    parser.add_argument("--zap", action="store_true", help="Lance ZAP meme en mode passif")
    parser.add_argument("--har", help="Importe un fichier HAR pour decouvrir les requetes dynamiques")
    parser.add_argument("--profile", choices=["auto", "global", "juice-shop"], default="auto")
    parser.add_argument("--output", default="results")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--max-pages", type=int, default=30)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--max-scripts", type=int, default=12)
    parser.add_argument("--max-active", type=int, default=12)
    parser.add_argument("--max-body", type=int, default=2_000_000)
    parser.add_argument("--no-tools", action="store_true", help="Ignore les outils externes Kali")
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
