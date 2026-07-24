#!/usr/bin/env python3
"""Importe un HAR et realise des tests actifs limites sur une cible autorisée.

Le script ne cherche pas à exploiter une vulnérabilité. Il rejoue uniquement des
requêtes de même origine, avec un nombre limité de mutations non destructives.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import html
import json
import re
import secrets
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

REQUEST_TIMEOUT = 12
MAX_RESPONSE_SIZE = 1_000_000
MAX_REQUEST_BODY = 100_000
USER_AGENT = "DevSecOps-Scanner/1.1.0"

SQL_ERROR_PATTERNS = {
    "SQLite": re.compile(r"(?:sqlite_error|sqlite exception|sqlite3?\.)", re.I),
    "Sequelize": re.compile(r"(?:sequelize(?:database)?error|sequelizequery)", re.I),
    "MySQL": re.compile(r"(?:you have an error in your sql syntax|mysql_fetch|mysqli?\.)", re.I),
    "PostgreSQL": re.compile(r"(?:postgresql|pg_query|syntax error at or near|psql:)", re.I),
    "Oracle": re.compile(r"\bORA-\d{4,5}\b", re.I),
    "SQLSTATE": re.compile(r"\bSQLSTATE\[[A-Z0-9]+\]", re.I),
    "Generic SQL": re.compile(r"(?:unterminated quoted string|quoted string not properly terminated)", re.I),
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

SENSITIVE_REPLAY_MARKERS = (
    "/logout",
    "/signout",
    "/delete",
    "/remove",
    "/checkout",
    "/payment",
    "/purchase",
    "/order",
    "/upload",
    "/admin",
    "/basket",
    "/cart",
    "/register",
    "/password",
    "/reset",
)

SAFE_HEADER_NAMES = {
    "accept",
    "accept-language",
    "content-type",
    "origin",
    "referer",
    "x-csrf-token",
    "x-xsrf-token",
    "x-requested-with",
}

AUTH_HEADER_NAMES = {"authorization", "cookie"}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass
class HttpResult:
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed: float
    error: str | None = None


@dataclass
class RequestTemplate:
    request_id: str
    method: str
    url: str
    headers: dict[str, str]
    content_type: str
    body_text: str
    body_json: Any | None
    source_index: int


def log(message: str) -> None:
    print(f" -> {message}")


def log_ok(message: str) -> None:
    print(f" [OK] {message}")


def log_warn(message: str) -> None:
    print(f" [!] {message}")


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def safe_json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def origin_tuple(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        parsed.port or default_port(parsed.scheme),
    )


def same_origin(url: str, target: str) -> bool:
    return origin_tuple(url) == origin_tuple(target)


def encode_url_for_request(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"URL HTTP invalide : {url}")

    hostname = parts.hostname.encode("idna").decode("ascii")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = hostname
    if parts.port:
        netloc += f":{parts.port}"

    encoded_path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    encoded_query = quote(parts.query, safe="=&%/:?@!$'()*+,;[]-._~")
    return urlunsplit((parts.scheme, netloc, encoded_path, encoded_query, ""))


def build_http_opener(url: str) -> Any:
    handlers: list[Any] = [NoRedirectHandler()]
    if urlsplit(url).scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=context))
    return build_opener(*handlers)


def request_url(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
) -> HttpResult:
    started = time.monotonic()
    encoded_url = encode_url_for_request(url)
    request_headers = dict(headers)
    request_headers["User-Agent"] = USER_AGENT
    request = Request(encoded_url, data=body, headers=request_headers, method=method)
    opener = build_http_opener(encoded_url)

    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT)
        raw = response.read(MAX_RESPONSE_SIZE + 1)[:MAX_RESPONSE_SIZE]
        text = raw.decode(response.headers.get_content_charset() or "utf-8", errors="replace")
        return HttpResult(
            url=encoded_url,
            status=int(response.status),
            headers={key.lower(): value for key, value in response.headers.items()},
            body=text,
            elapsed=round(time.monotonic() - started, 4),
        )
    except HTTPError as error:
        raw = error.read(MAX_RESPONSE_SIZE + 1)[:MAX_RESPONSE_SIZE]
        text = raw.decode(error.headers.get_content_charset() or "utf-8", errors="replace")
        return HttpResult(
            url=encoded_url,
            status=int(error.code),
            headers={key.lower(): value for key, value in error.headers.items()},
            body=text,
            elapsed=round(time.monotonic() - started, 4),
            error=str(error),
        )
    except (URLError, TimeoutError, OSError, UnicodeError, ValueError) as error:
        return HttpResult(
            url=encoded_url,
            status=0,
            headers={},
            body="",
            elapsed=round(time.monotonic() - started, 4),
            error=str(error),
        )


def body_hash(body: str) -> str:
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:16]


def sanitize_url(url: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    query = urlencode([(name, "[redacted]") for name, _value in pairs], doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))




def decode_base64url_json(value: str) -> dict[str, Any] | None:
    try:
        padding = "=" * (-len(value) % 4)
        raw = base64.urlsafe_b64decode((value + padding).encode("ascii"))
        parsed = json.loads(raw.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None


def jwt_candidates_from_headers(items: Iterable[dict[str, Any]]) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    jwt_pattern = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")
    for item in items:
        name = str(item.get("name", ""))
        value = str(item.get("value", ""))
        for match in jwt_pattern.finditer(value):
            candidates.append((name, match.group(0)))
    return candidates


def analyse_jwts_in_har(har_path: Path, target: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    data = safe_json_load(har_path)
    entries = data.get("log", {}).get("entries", []) if isinstance(data, dict) else []
    analyses: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    sensitive_claims = {"password", "passwd", "secret", "api_key", "apikey", "creditcard", "cardnumber"}

    for index, entry in enumerate(entries if isinstance(entries, list) else []):
        request = entry.get("request", {}) if isinstance(entry, dict) else {}
        url = str(request.get("url", ""))
        if not url or not same_origin(url, target):
            continue
        for header_name, token in jwt_candidates_from_headers(request.get("headers", [])):
            fingerprint = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()[:12]
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            parts = token.split(".")
            header = decode_base64url_json(parts[0]) if len(parts) == 3 else None
            payload = decode_base64url_json(parts[1]) if len(parts) == 3 else None
            if header is None or payload is None:
                continue
            alg = str(header.get("alg", "non renseigne"))
            exp = payload.get("exp")
            iat = payload.get("iat")
            claim_names = sorted(str(key) for key in payload.keys())
            analysis = {
                "fingerprint": fingerprint,
                "source": header_name,
                "request_path": urlsplit(url).path or "/",
                "algorithm": alg,
                "has_exp": isinstance(exp, (int, float)),
                "has_iat": isinstance(iat, (int, float)),
                "lifetime_seconds": (exp - iat) if isinstance(exp, (int, float)) and isinstance(iat, (int, float)) else None,
                "claim_names": claim_names,
            }
            analyses.append(analysis)

            if alg.lower() == "none":
                add_finding(
                    findings,
                    title="JWT utilisant l'algorithme none",
                    category="Token Security",
                    severity="high",
                    confidence="confirmed",
                    tool="HAR JWT analysis",
                    evidence=f"JWT {fingerprint}, chemin {analysis['request_path']}: alg=none.",
                    description="Le token annonce une absence de signature. Le comportement du serveur doit etre verifie.",
                    endpoint=analysis["request_path"],
                    parameter=header_name,
                )
            if not analysis["has_exp"]:
                add_finding(
                    findings,
                    title="JWT sans date d'expiration",
                    category="Token Security",
                    severity="medium",
                    confidence="confirmed",
                    tool="HAR JWT analysis",
                    evidence=f"JWT {fingerprint}, chemin {analysis['request_path']}: claim exp absente.",
                    description="Un token sans expiration explicite peut rester valide plus longtemps que necessaire.",
                    endpoint=analysis["request_path"],
                    parameter=header_name,
                )
            lifetime = analysis.get("lifetime_seconds")
            if isinstance(lifetime, (int, float)) and lifetime > 86400:
                add_finding(
                    findings,
                    title="Duree de validite JWT longue",
                    category="Token Security",
                    severity="low",
                    confidence="possible",
                    tool="HAR JWT analysis",
                    evidence=f"JWT {fingerprint}: duree annoncee de {int(lifetime)} secondes.",
                    description="La criticite depend du type de token et des mecanismes de revocation.",
                    endpoint=analysis["request_path"],
                    parameter=header_name,
                )
            exposed = sorted(sensitive_claims.intersection({name.lower() for name in claim_names}))
            if exposed:
                add_finding(
                    findings,
                    title="Donnees sensibles potentielles dans un JWT",
                    category="Sensitive Data Exposure",
                    severity="medium",
                    confidence="confirmed",
                    tool="HAR JWT analysis",
                    evidence=f"JWT {fingerprint}: claims sensibles {', '.join(exposed)}.",
                    description="Le contenu d'un JWT signe est lisible par son porteur et ne doit pas contenir de secrets.",
                    endpoint=analysis["request_path"],
                    parameter=header_name,
                )

    return analyses, deduplicate_findings(findings)

def header_map(items: Iterable[dict[str, Any]], use_auth: bool) -> dict[str, str]:
    output: dict[str, str] = {}
    for item in items:
        name = str(item.get("name", "")).strip()
        value = str(item.get("value", ""))
        lowered = name.lower()
        if lowered in SAFE_HEADER_NAMES or (use_auth and lowered in AUTH_HEADER_NAMES):
            output[name] = value
    return output


def json_scalar_paths(value: Any, prefix: tuple[Any, ...] = ()) -> list[tuple[tuple[Any, ...], Any]]:
    output: list[tuple[tuple[Any, ...], Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            output.extend(json_scalar_paths(item, prefix + (key,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            output.extend(json_scalar_paths(item, prefix + (index,)))
    else:
        output.append((prefix, value))
    return output


def set_json_path(value: Any, path: tuple[Any, ...], replacement: Any) -> Any:
    cloned = copy.deepcopy(value)
    current = cloned
    for token in path[:-1]:
        current = current[token]
    if path:
        current[path[-1]] = replacement
    return cloned


def parameter_name_from_path(path: tuple[Any, ...]) -> str:
    if not path:
        return "$"
    parts: list[str] = []
    for token in path:
        if isinstance(token, int):
            parts.append(f"[{token}]")
        elif parts:
            parts.append(f".{token}")
        else:
            parts.append(str(token))
    return "".join(parts)


def load_har(
    har_path: Path,
    target: str,
    use_auth: bool,
) -> tuple[list[RequestTemplate], list[dict[str, Any]], list[dict[str, Any]]]:
    data = safe_json_load(har_path)
    entries = data.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Format HAR invalide : log.entries absent.")

    templates: list[RequestTemplate] = []
    requests_inventory: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    seen_parameters: set[tuple[str, str, str, str]] = set()

    for index, entry in enumerate(entries):
        request = entry.get("request", {})
        method = str(request.get("method", "GET")).upper()
        url = str(request.get("url", ""))
        if not url or not same_origin(url, target):
            continue

        headers = header_map(request.get("headers", []), use_auth)
        post_data = request.get("postData") or {}
        content_type = str(post_data.get("mimeType") or headers.get("Content-Type") or "")
        body_text = str(post_data.get("text") or "")
        body_json: Any | None = None
        request_id = f"har-{index:04d}"

        if len(body_text.encode("utf-8", errors="replace")) > MAX_REQUEST_BODY:
            body_text = ""

        if "json" in content_type.lower() and body_text:
            try:
                body_json = json.loads(body_text)
            except json.JSONDecodeError:
                body_json = None

        template = RequestTemplate(
            request_id=request_id,
            method=method,
            url=url,
            headers=headers,
            content_type=content_type,
            body_text=body_text,
            body_json=body_json,
            source_index=index,
        )
        templates.append(template)

        parsed = urlsplit(url)
        requests_inventory.append(
            {
                "request_id": request_id,
                "method": method,
                "url": sanitize_url(url),
                "path": parsed.path or "/",
                "content_type": content_type,
                "has_body": bool(body_text),
                "authenticated_headers_replayed": bool(use_auth and any(k.lower() in AUTH_HEADER_NAMES for k in headers)),
            }
        )

        query_items = request.get("queryString") or [
            {"name": name, "value": value}
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        for item in query_items:
            name = str(item.get("name", "")).strip()
            if not name:
                continue
            key = (method, parsed.path or "/", "query", name)
            if key in seen_parameters:
                continue
            seen_parameters.add(key)
            parameters.append(
                {
                    "request_id": request_id,
                    "method": method,
                    "path": parsed.path or "/",
                    "url": sanitize_url(url),
                    "name": name,
                    "location": "query",
                    "value_type": "string",
                    "active_testable": method in {"GET", "HEAD"},
                    "source": "har",
                }
            )

        lowered_content_type = content_type.lower()
        if body_json is not None:
            for json_path, original in json_scalar_paths(body_json):
                name = parameter_name_from_path(json_path)
                key = (method, parsed.path or "/", "json", name)
                if key in seen_parameters:
                    continue
                seen_parameters.add(key)
                parameters.append(
                    {
                        "request_id": request_id,
                        "method": method,
                        "path": parsed.path or "/",
                        "url": sanitize_url(url),
                        "name": name,
                        "location": "json",
                        "json_path": list(json_path),
                        "value_type": type(original).__name__,
                        "active_testable": method in {"POST", "PUT", "PATCH"},
                        "source": "har",
                    }
                )
        elif "application/x-www-form-urlencoded" in lowered_content_type and body_text:
            for name, _value in parse_qsl(body_text, keep_blank_values=True):
                key = (method, parsed.path or "/", "form", name)
                if key in seen_parameters:
                    continue
                seen_parameters.add(key)
                parameters.append(
                    {
                        "request_id": request_id,
                        "method": method,
                        "path": parsed.path or "/",
                        "url": sanitize_url(url),
                        "name": name,
                        "location": "form",
                        "value_type": "string",
                        "active_testable": method in {"POST", "PUT", "PATCH"},
                        "source": "har",
                    }
                )
        elif post_data.get("params"):
            for item in post_data.get("params", []):
                name = str(item.get("name", "")).strip()
                if not name:
                    continue
                key = (method, parsed.path or "/", "multipart", name)
                if key in seen_parameters:
                    continue
                seen_parameters.add(key)
                parameters.append(
                    {
                        "request_id": request_id,
                        "method": method,
                        "path": parsed.path or "/",
                        "url": sanitize_url(url),
                        "name": name,
                        "location": "multipart",
                        "value_type": "file" if item.get("fileName") else "string",
                        "active_testable": False,
                        "source": "har",
                    }
                )

    return templates, requests_inventory, parameters


def replace_query_value(url: str, name: str, replacement: str) -> str:
    parts = urlsplit(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == name and not replaced:
            output.append((key, replacement))
            replaced = True
        else:
            output.append((key, value))
    if not replaced:
        output.append((name, replacement))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(output, doseq=True), ""))


def replace_form_value(body: str, name: str, replacement: str) -> str:
    pairs = parse_qsl(body, keep_blank_values=True)
    replaced = False
    output: list[tuple[str, str]] = []
    for key, value in pairs:
        if key == name and not replaced:
            output.append((key, replacement))
            replaced = True
        else:
            output.append((key, value))
    if not replaced:
        output.append((name, replacement))
    return urlencode(output, doseq=True)


def json_type_mutation(original: Any) -> Any:
    if isinstance(original, bool):
        return "WSS_TYPE_STRING"
    if isinstance(original, (int, float)) and not isinstance(original, bool):
        return "WSS_TYPE_STRING"
    if original is None:
        return "WSS_TYPE_STRING"
    return 12345


def build_mutations(parameter: dict[str, Any], token: str, original_json_value: Any | None) -> list[tuple[str, Any]]:
    marker = f"WSS_REFLECT_{token}"
    special = f"WSS_{token}_'\"<>"
    mutations: list[tuple[str, Any]] = [
        ("empty", ""),
        ("reflection_marker", marker),
        ("special_characters", special),
        ("sql_quote_marker", f"WSS_SQL_{token}'"),
    ]
    if parameter.get("location") == "json":
        mutations.append(("json_type_mismatch", json_type_mutation(original_json_value)))
    if str(parameter.get("name", "")).lower().split(".")[-1] in REDIRECT_PARAMETER_NAMES:
        mutations.append(("external_redirect", "https://scanner.invalid/"))
    return mutations


def build_request_variant(
    template: RequestTemplate,
    parameter: dict[str, Any],
    replacement: Any,
) -> tuple[str, bytes | None]:
    location = parameter.get("location")
    url = template.url
    body: bytes | None = template.body_text.encode("utf-8") if template.body_text else None

    if location == "query":
        url = replace_query_value(template.url, str(parameter["name"]), str(replacement))
    elif location == "form":
        body_text = replace_form_value(template.body_text, str(parameter["name"]), str(replacement))
        body = body_text.encode("utf-8")
    elif location == "json":
        if template.body_json is None:
            raise ValueError("Corps JSON absent.")
        path = tuple(parameter.get("json_path", []))
        mutated = set_json_path(template.body_json, path, replacement)
        body = json.dumps(mutated, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    else:
        raise ValueError(f"Emplacement non testable : {location}")

    return url, body


def original_json_value(template: RequestTemplate, parameter: dict[str, Any]) -> Any | None:
    if template.body_json is None:
        return None
    current = template.body_json
    for token in parameter.get("json_path", []):
        current = current[token]
    return current


def is_sensitive_replay(template: RequestTemplate) -> bool:
    path = (urlsplit(template.url).path or "/").lower()
    return any(marker in path for marker in SENSITIVE_REPLAY_MARKERS)


def response_summary(result: HttpResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "length": len(result.body.encode("utf-8", errors="replace")),
        "elapsed": result.elapsed,
        "body_hash": body_hash(result.body),
        "content_type": result.headers.get("content-type", ""),
        "location": result.headers.get("location", ""),
        "error": result.error,
    }


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
    endpoint: str,
    parameter: str,
) -> None:
    findings.append(
        {
            "title": title,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "tool": tool,
            "evidence": evidence,
            "description": description,
            "endpoint": endpoint,
            "parameter": parameter,
        }
    )


def find_sql_error(body: str) -> str | None:
    for name, pattern in SQL_ERROR_PATTERNS.items():
        if pattern.search(body):
            return name
    return None


def analyse_mutation(
    *,
    template: RequestTemplate,
    parameter: dict[str, Any],
    mutation_name: str,
    replacement: Any,
    baseline: HttpResult,
    result: HttpResult,
    findings: list[dict[str, Any]],
) -> list[str]:
    signals: list[str] = []
    endpoint = f"{template.method} {urlsplit(template.url).path or '/'}"
    parameter_name = str(parameter.get("name", ""))
    baseline_sql = find_sql_error(baseline.body)
    mutated_sql = find_sql_error(result.body)

    if baseline.status and baseline.status < 500 and result.status >= 500:
        signals.append("server_error")
        add_finding(
            findings,
            title="Erreur serveur provoquee par une entree modifiee",
            category="Improper Input Validation",
            severity="medium",
            confidence="probable",
            tool="HAR active tests",
            evidence=f"{endpoint}, parametre {parameter_name}: HTTP {baseline.status} puis HTTP {result.status} avec {mutation_name}.",
            description="Une entree inhabituelle provoque une erreur serveur. La cause doit etre confirmee manuellement.",
            endpoint=endpoint,
            parameter=parameter_name,
        )

    if mutated_sql and not baseline_sql:
        signals.append("sql_error")
        add_finding(
            findings,
            title="Indice d'injection SQL",
            category="Injection",
            severity="high",
            confidence="probable",
            tool="HAR active tests",
            evidence=f"{endpoint}, parametre {parameter_name}: erreur {mutated_sql} apparue avec {mutation_name}.",
            description="Une erreur de base de donnees apparait apres modification du parametre. Ce resultat ne constitue pas une exploitation.",
            endpoint=endpoint,
            parameter=parameter_name,
        )

    replacement_text = str(replacement)
    if replacement_text.startswith("WSS_REFLECT_") and replacement_text in result.body:
        signals.append("reflected")
        add_finding(
            findings,
            title="Entree utilisateur reflechie dans la reponse",
            category="XSS",
            severity="low",
            confidence="possible",
            tool="HAR active tests",
            evidence=f"{endpoint}, parametre {parameter_name}: marqueur unique retrouve dans la reponse.",
            description="La reflexion doit etre analysee dans son contexte HTML ou JavaScript avant de conclure a une XSS.",
            endpoint=endpoint,
            parameter=parameter_name,
        )

    if mutation_name == "special_characters":
        raw_special = replacement_text in result.body
        escaped_special = html.escape(replacement_text, quote=True) in result.body
        content_type = result.headers.get("content-type", "").lower()
        if raw_special and "html" in content_type:
            signals.append("raw_html_reflection")
            add_finding(
                findings,
                title="XSS reflechie potentielle",
                category="XSS",
                severity="medium",
                confidence="possible",
                tool="HAR active tests",
                evidence=f"{endpoint}, parametre {parameter_name}: caracteres HTML reflechis sans encodage apparent.",
                description="Le scanner utilise un marqueur non executable. Une validation dans le navigateur reste necessaire.",
                endpoint=endpoint,
                parameter=parameter_name,
            )
        elif escaped_special:
            signals.append("escaped_reflection")

    if mutation_name == "external_redirect" and result.status in {301, 302, 303, 307, 308}:
        location = result.headers.get("location", "")
        if (urlsplit(location).hostname or "").lower() == "scanner.invalid":
            signals.append("open_redirect")
            add_finding(
                findings,
                title="Redirection externe non validee",
                category="Unvalidated Redirects",
                severity="medium",
                confidence="confirmed",
                tool="HAR active tests",
                evidence=f"{endpoint}, parametre {parameter_name}: HTTP {result.status}, Location vers scanner.invalid.",
                description="Le parametre permet une redirection vers un domaine externe controle par l'utilisateur.",
                endpoint=endpoint,
                parameter=parameter_name,
            )

    return signals


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in findings:
        key = (
            str(item.get("title", "")).lower(),
            str(item.get("endpoint", "")).lower(),
            str(item.get("parameter", "")).lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def run_active_tests(
    *,
    templates: list[RequestTemplate],
    parameters: list[dict[str, Any]],
    allow_post: bool,
    max_targets: int,
    delay: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    templates_by_id = {template.request_id: template for template in templates}
    findings: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    tested = 0

    for parameter in parameters:
        if tested >= max_targets:
            break
        template = templates_by_id.get(str(parameter.get("request_id")))
        if template is None:
            continue

        location = parameter.get("location")
        if location == "query" and template.method not in {"GET", "HEAD"}:
            continue
        if location in {"form", "json"}:
            if not allow_post or template.method not in {"POST", "PUT", "PATCH"}:
                continue
            if is_sensitive_replay(template):
                continue
        if location not in {"query", "form", "json"}:
            continue

        log(f"Test actif {tested + 1}/{max_targets} : {template.method} {urlsplit(template.url).path} -> {parameter.get('name')}")
        baseline_body = template.body_text.encode("utf-8") if template.body_text else None
        baseline = request_url(
            method=template.method,
            url=template.url,
            headers=template.headers,
            body=baseline_body,
        )
        token = secrets.token_hex(4).upper()
        original = original_json_value(template, parameter)
        record = {
            "request_id": template.request_id,
            "method": template.method,
            "url": sanitize_url(template.url),
            "path": urlsplit(template.url).path or "/",
            "parameter": parameter.get("name"),
            "location": location,
            "baseline": response_summary(baseline),
            "mutations": [],
        }

        for mutation_name, replacement in build_mutations(parameter, token, original):
            try:
                mutated_url, mutated_body = build_request_variant(template, parameter, replacement)
            except (KeyError, TypeError, ValueError, IndexError) as error:
                record["mutations"].append({"name": mutation_name, "error": str(error)})
                continue

            result = request_url(
                method=template.method,
                url=mutated_url,
                headers=template.headers,
                body=mutated_body,
            )
            signals = analyse_mutation(
                template=template,
                parameter=parameter,
                mutation_name=mutation_name,
                replacement=replacement,
                baseline=baseline,
                result=result,
                findings=findings,
            )
            record["mutations"].append(
                {
                    "name": mutation_name,
                    "response": response_summary(result),
                    "signals": signals,
                }
            )
            if delay > 0:
                time.sleep(delay)

        results.append(record)
        tested += 1

    return results, deduplicate_findings(findings)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import HAR et tests actifs limites")
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True, help="Dossier de sortie du scan")
    parser.add_argument("--har", help="Fichier HAR exporte depuis Burp, Firefox ou Chromium")
    parser.add_argument("--mode", choices=["passive", "active"], default="passive")
    parser.add_argument("--active-post", action="store_true", help="Autorise les mutations POST/PUT/PATCH non sensibles")
    parser.add_argument("--use-har-auth", action="store_true", help="Rejoue Authorization et Cookie du HAR sans les enregistrer")
    parser.add_argument("--max-active-targets", type=int, default=15)
    parser.add_argument("--delay", type=float, default=0.15)
    args = parser.parse_args()

    output_dir = Path(args.input)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not args.har:
        write_json(output_dir / "har-requests.json", [])
        write_json(output_dir / "dynamic-parameters.json", [])
        write_json(output_dir / "dynamic-tests.json", [])
        write_json(output_dir / "dynamic-findings.json", [])
        write_json(output_dir / "jwt-analysis.json", [])
        log_warn("Aucun fichier HAR fourni : analyse dynamique ignoree.")
        return

    har_path = Path(args.har).expanduser().resolve()
    if not har_path.is_file():
        raise SystemExit(f"Fichier HAR introuvable : {har_path}")

    log(f"Lecture du HAR : {har_path}")
    jwt_analyses, jwt_findings = analyse_jwts_in_har(har_path, args.target)
    write_json(output_dir / "jwt-analysis.json", jwt_analyses)
    templates, requests_inventory, parameters = load_har(
        har_path,
        args.target,
        args.use_har_auth,
    )
    write_json(output_dir / "har-requests.json", requests_inventory)
    write_json(output_dir / "dynamic-parameters.json", parameters)
    log_ok(f"{len(requests_inventory)} requete(s) de meme origine et {len(parameters)} parametre(s) inventories.")

    if args.mode != "active":
        write_json(output_dir / "dynamic-tests.json", [])
        write_json(output_dir / "dynamic-findings.json", jwt_findings)
        log_ok(f"Mode passif : aucune requete HAR rejouee ; {len(jwt_analyses)} JWT analyse(s).")
        return

    tests, findings = run_active_tests(
        templates=templates,
        parameters=parameters,
        allow_post=args.active_post,
        max_targets=max(1, min(args.max_active_targets, 50)),
        delay=max(0.0, min(args.delay, 2.0)),
    )
    findings = deduplicate_findings(jwt_findings + findings)
    write_json(output_dir / "dynamic-tests.json", tests)
    write_json(output_dir / "dynamic-findings.json", findings)
    log_ok(f"{len(tests)} parametre(s) teste(s), {len(jwt_analyses)} JWT analyse(s), {len(findings)} constat(s) dynamique(s).")


if __name__ == "__main__":
    main()
