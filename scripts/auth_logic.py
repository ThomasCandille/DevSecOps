#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import re
import ssl
import statistics
import time
import uuid
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

REQUEST_TIMEOUT = 12
MAX_RESPONSE_SIZE = 1_000_000
USER_AGENT = "DevSecOps-Scanner/1.1.0"
STATIC_EXTENSIONS = {
    ".css", ".gif", ".ico", ".jpeg", ".jpg", ".js", ".map", ".png",
    ".svg", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webm",
}
AUTH_HEADERS = {"authorization", "cookie"}
SAFE_REPLAY_HEADERS = {
    "accept", "accept-language", "content-type", "origin", "referer",
    "x-csrf-token", "x-xsrf-token", "x-requested-with",
}
LOGIN_MARKERS = ("/login", "/signin", "/sign-in", "/authenticate", "/session")
LOGOUT_MARKERS = ("/logout", "/signout", "/sign-out", "/session/end")
PRIVATE_ROUTE_MARKERS = (
    "/user", "/users", "/account", "/profile", "/basket", "/cart", "/order",
    "/address", "/payment", "/invoice", "/document", "/file", "/feedback",
    "/message", "/notification", "/admin", "/private", "/me", "/session",
)
ID_NAMES = {
    "id", "userid", "user_id", "accountid", "account_id", "profileid", "profile_id",
    "basketid", "basket_id", "cartid", "cart_id", "orderid", "order_id",
    "addressid", "address_id", "paymentid", "payment_id", "documentid", "document_id",
    "fileid", "file_id", "ownerid", "owner_id", "customerid", "customer_id",
}
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{20,}\b")
NUMBER_RE = re.compile(r"\b\d{2,}\b")
SENSITIVE_RESPONSE_KEYS = {
    "email", "username", "firstname", "lastname", "address", "phone", "token",
    "password", "card", "account", "owner", "user", "customer", "invoice",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
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
class HarRequest:
    index: int
    method: str
    url: str
    headers: dict[str, str]
    body: str
    content_type: str
    response_status: int
    response_body: str


def log(message: str) -> None:
    print(f" -> {message}")


def log_ok(message: str) -> None:
    print(f" [OK] {message}")


def log_warn(message: str) -> None:
    print(f" [!] {message}")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path, default: Any) -> Any:
    if not path or not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def origin_tuple(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port or default_port(parsed.scheme)


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
    path = quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    query = quote(parts.query, safe="=&%/:?@!$'()*+,;[]-._~")
    return urlunsplit((parts.scheme, netloc, path, query, ""))


def build_http_opener(url: str) -> Any:
    handlers: list[Any] = [NoRedirectHandler()]
    if urlsplit(url).scheme == "https":
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(HTTPSHandler(context=context))
    return build_opener(*handlers)


def request_url(method: str, url: str, headers: dict[str, str], body: bytes | None = None) -> HttpResult:
    started = time.monotonic()
    try:
        encoded = encode_url_for_request(url)
        request_headers = dict(headers)
        request_headers["User-Agent"] = USER_AGENT
        request = Request(encoded, data=body, headers=request_headers, method=method.upper())
        response = build_http_opener(encoded).open(request, timeout=REQUEST_TIMEOUT)
        raw = response.read(MAX_RESPONSE_SIZE + 1)[:MAX_RESPONSE_SIZE]
        charset = response.headers.get_content_charset() or "utf-8"
        return HttpResult(
            url=encoded,
            status=int(response.status),
            headers={k.lower(): v for k, v in response.headers.items()},
            body=raw.decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 4),
        )
    except HTTPError as error:
        raw = error.read(MAX_RESPONSE_SIZE + 1)[:MAX_RESPONSE_SIZE]
        charset = error.headers.get_content_charset() or "utf-8"
        return HttpResult(
            url=url,
            status=int(error.code),
            headers={k.lower(): v for k, v in error.headers.items()},
            body=raw.decode(charset, errors="replace"),
            elapsed=round(time.monotonic() - started, 4),
            error=str(error),
        )
    except (URLError, TimeoutError, OSError, UnicodeError, ValueError) as error:
        return HttpResult(
            url=url,
            status=0,
            headers={},
            body="",
            elapsed=round(time.monotonic() - started, 4),
            error=str(error),
        )


def decode_har_content(content: dict[str, Any]) -> str:
    text = str(content.get("text", "") or "")
    if content.get("encoding") == "base64" and text:
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except (ValueError, OSError):
            return ""
    return text


def headers_to_dict(items: Iterable[dict[str, Any]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items:
        name = str(item.get("name", "")).strip().lower()
        value = str(item.get("value", ""))
        if name:
            result[name] = value
    return result


def load_har(path: Path | None, target: str) -> list[HarRequest]:
    if path is None:
        return []
    payload = read_json(path, {})
    entries = payload.get("log", {}).get("entries", []) if isinstance(payload, dict) else []
    requests: list[HarRequest] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = str(req.get("url", ""))
        if not url or not same_origin(url, target):
            continue
        headers = headers_to_dict(req.get("headers", []))
        post_data = req.get("postData", {}) if isinstance(req.get("postData"), dict) else {}
        content_type = str(post_data.get("mimeType") or headers.get("content-type", ""))
        body = str(post_data.get("text", "") or "")
        response_content = res.get("content", {}) if isinstance(res.get("content"), dict) else {}
        requests.append(HarRequest(
            index=index,
            method=str(req.get("method", "GET")).upper(),
            url=url,
            headers=headers,
            body=body,
            content_type=content_type,
            response_status=int(res.get("status", 0) or 0),
            response_body=decode_har_content(response_content),
        ))
    return requests


def auth_headers(requests: list[HarRequest]) -> dict[str, str]:
    for item in reversed(requests):
        selected = {
            name: value for name, value in item.headers.items()
            if name in AUTH_HEADERS or name in SAFE_REPLAY_HEADERS
        }
        if any(name in selected for name in AUTH_HEADERS):
            return selected
    return {}


def redact_url(url: str) -> str:
    parts = urlsplit(url)
    names = [name for name, _ in parse_qsl(parts.query, keep_blank_values=True)]
    query = urlencode([(name, "<redacted>") for name in names], doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def response_summary(result: HttpResult) -> dict[str, Any]:
    return {
        "status": result.status,
        "length": len(result.body.encode("utf-8", errors="ignore")),
        "elapsed": result.elapsed,
        "content_type": result.headers.get("content-type", ""),
        "location": result.headers.get("location", ""),
        "body_hash": hashlib.sha256(normalize_body(result.body).encode("utf-8")).hexdigest()[:16],
        "error": result.error,
    }


def normalize_body(body: str) -> str:
    value = TOKEN_RE.sub("<token>", body)
    value = NUMBER_RE.sub("<number>", value)
    value = re.sub(r"\s+", " ", value).strip()
    return value[:250_000]


def body_similarity(left: str, right: str) -> float:
    a = normalize_body(left)
    b = normalize_body(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    return round(SequenceMatcher(None, a[:100_000], b[:100_000]).ratio(), 4)


def has_sensitive_json(body: str) -> bool:
    try:
        value = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        lowered = body.lower()
        return any(f'"{key}"' in lowered or f"'{key}'" in lowered for key in SENSITIVE_RESPONSE_KEYS)

    def walk(node: Any) -> bool:
        if isinstance(node, dict):
            for key, child in node.items():
                if str(key).lower() in SENSITIVE_RESPONSE_KEYS:
                    return True
                if walk(child):
                    return True
        elif isinstance(node, list):
            return any(walk(child) for child in node[:50])
        return False

    return walk(value)


def is_static(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def is_private_candidate(item: HarRequest) -> bool:
    path = urlsplit(item.url).path.lower()
    query_names = {name.lower() for name, _ in parse_qsl(urlsplit(item.url).query, keep_blank_values=True)}
    segments = [segment for segment in path.split("/") if segment]
    has_identifier = any(segment.isdigit() or UUID_RE.fullmatch(segment) for segment in segments)
    has_id_query = bool(query_names & ID_NAMES) or any(name.endswith("id") for name in query_names)
    private_marker = any(marker in path for marker in PRIVATE_ROUTE_MARKERS)
    return item.method in {"GET", "HEAD"} and not is_static(item.url) and (private_marker and (has_identifier or has_id_query))


def select_protected_probe(requests: list[HarRequest]) -> HarRequest | None:
    candidates = [
        item for item in requests
        if item.method in {"GET", "HEAD"}
        and 200 <= item.response_status < 300
        and not is_static(item.url)
        and not any(marker in urlsplit(item.url).path.lower() for marker in LOGIN_MARKERS + LOGOUT_MARKERS)
        and any(name in item.headers for name in AUTH_HEADERS)
    ]
    private = [item for item in candidates if any(marker in urlsplit(item.url).path.lower() for marker in PRIVATE_ROUTE_MARKERS)]
    return (private or candidates)[-1] if (private or candidates) else None


def select_logout(requests: list[HarRequest]) -> HarRequest | None:
    for item in reversed(requests):
        path = urlsplit(item.url).path.lower()
        if any(marker in path for marker in LOGOUT_MARKERS):
            return item
    return None


def replay_headers(item: HarRequest, auth: dict[str, str]) -> dict[str, str]:
    selected = {
        name: value for name, value in item.headers.items()
        if name in SAFE_REPLAY_HEADERS
    }
    selected.update(auth)
    return selected


def body_bytes(item: HarRequest) -> bytes | None:
    return item.body.encode("utf-8") if item.body else None


def finding(title: str, category: str, severity: str, confidence: str, evidence: str, description: str, tool: str) -> dict[str, Any]:
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "description": description,
        "tool": tool,
    }


def run_access_tests(
    target: str,
    user_a: list[HarRequest],
    user_b: list[HarRequest],
    max_tests: int,
    delay: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    auth_a = auth_headers(user_a)
    auth_b = auth_headers(user_b)
    if not auth_a or not auth_b:
        return tests, findings

    pairs = [("user_a", user_a, auth_a, "user_b", auth_b), ("user_b", user_b, auth_b, "user_a", auth_a)]
    tested_urls: set[str] = set()
    for owner_name, owner_requests, owner_auth, other_name, other_auth in pairs:
        for template in owner_requests:
            if len(tests) >= max_tests:
                break
            if not is_private_candidate(template) or template.url in tested_urls:
                continue
            tested_urls.add(template.url)
            log(f"Controle d'acces : {template.method} {urlsplit(template.url).path} ({owner_name} -> {other_name})")
            baseline = request_url(template.method, template.url, replay_headers(template, owner_auth), body_bytes(template))
            time.sleep(delay)
            other = request_url(template.method, template.url, replay_headers(template, other_auth), body_bytes(template))
            time.sleep(delay)
            anonymous = request_url(template.method, template.url, replay_headers(template, {}), body_bytes(template))
            similarity_other = body_similarity(baseline.body, other.body)
            similarity_anonymous = body_similarity(baseline.body, anonymous.body)
            test = {
                "test_id": f"access-{len(tests)+1:03d}",
                "owner": owner_name,
                "other_user": other_name,
                "method": template.method,
                "url": redact_url(template.url),
                "baseline": response_summary(baseline),
                "other_user_response": response_summary(other),
                "anonymous_response": response_summary(anonymous),
                "similarity_other": similarity_other,
                "similarity_anonymous": similarity_anonymous,
                "result": "passed",
            }
            if 200 <= baseline.status < 300 and 200 <= other.status < 300 and similarity_other >= 0.82:
                test["result"] = "finding"
                severity = "high" if has_sensitive_json(baseline.body) else "medium"
                findings.append(finding(
                    "Controle d'acces objet potentiellement insuffisant",
                    "Broken Access Control / BOLA",
                    severity,
                    "probable",
                    f"{other_name} obtient HTTP {other.status} sur une ressource observee avec {owner_name}; similarite {similarity_other:.2f}.",
                    "La ressource d'un compte semble accessible depuis une autre session. Valider la propriete de l'objet et le contenu retourne.",
                    "Access control tests",
                ))
            if 200 <= baseline.status < 300 and 200 <= anonymous.status < 300 and similarity_anonymous >= 0.82:
                test["result"] = "finding"
                severity = "high" if has_sensitive_json(baseline.body) else "medium"
                findings.append(finding(
                    "Ressource authentifiee potentiellement accessible sans session",
                    "Broken Access Control",
                    severity,
                    "probable",
                    f"Acces anonyme HTTP {anonymous.status}; similarite avec la reponse authentifiee {similarity_anonymous:.2f}.",
                    "Une route contenant un identifiant semble fournir une reponse similaire sans authentification.",
                    "Access control tests",
                ))
            tests.append(test)
        if len(tests) >= max_tests:
            break
    return tests, findings


def run_session_test(user_a: list[HarRequest], delay: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    auth = auth_headers(user_a)
    logout = select_logout(user_a)
    probe = select_protected_probe(user_a)
    if not auth or not logout or not probe:
        tests.append({
            "test_id": "session-001",
            "result": "skipped",
            "reason": "Session, requete de deconnexion ou route protegee introuvable dans le HAR utilisateur A.",
        })
        return tests, findings

    log(f"Session : validation avant/apres deconnexion sur {urlsplit(probe.url).path}")
    before = request_url(probe.method, probe.url, replay_headers(probe, auth), body_bytes(probe))
    time.sleep(delay)
    logout_result = request_url(logout.method, logout.url, replay_headers(logout, auth), body_bytes(logout))
    time.sleep(delay)
    after = request_url(probe.method, probe.url, replay_headers(probe, auth), body_bytes(probe))
    similarity = body_similarity(before.body, after.body)
    result = "passed"
    if 200 <= before.status < 300 and 200 <= after.status < 300 and similarity >= 0.80:
        result = "finding"
        findings.append(finding(
            "Session potentiellement encore valide apres deconnexion",
            "Broken Authentication / Session Management",
            "high",
            "probable",
            f"Avant logout HTTP {before.status}, logout HTTP {logout_result.status}, apres logout HTTP {after.status}, similarite {similarity:.2f}.",
            "L'ancien cookie ou token semble encore permettre l'acces a une route protegee apres la deconnexion.",
            "Session invalidation test",
        ))
    tests.append({
        "test_id": "session-001",
        "probe_url": redact_url(probe.url),
        "logout_url": redact_url(logout.url),
        "before": response_summary(before),
        "logout": response_summary(logout_result),
        "after": response_summary(after),
        "similarity_before_after": similarity,
        "result": result,
    })
    return tests, findings


def substitute(value: Any, variables: dict[str, Any]) -> Any:
    if isinstance(value, str):
        result = value
        for name, replacement in variables.items():
            result = result.replace("{{" + name + "}}", str(replacement))
        return result
    if isinstance(value, list):
        return [substitute(item, variables) for item in value]
    if isinstance(value, dict):
        return {key: substitute(item, variables) for key, item in value.items()}
    return value


def encode_config_body(request_config: dict[str, Any], variables: dict[str, Any]) -> tuple[bytes | None, dict[str, str]]:
    headers = {str(k): str(v) for k, v in substitute(request_config.get("headers", {}), variables).items()}
    if "json" in request_config:
        headers.setdefault("Content-Type", "application/json")
        return json.dumps(substitute(request_config["json"], variables), ensure_ascii=False).encode("utf-8"), headers
    if "form" in request_config:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return urlencode(substitute(request_config["form"], variables), doseq=True).encode("utf-8"), headers
    body = substitute(request_config.get("body", ""), variables)
    return (str(body).encode("utf-8") if body != "" else None), headers


def configured_request(target: str, request_config: dict[str, Any], variables: dict[str, Any], auth_map: dict[str, dict[str, str]]) -> tuple[str, str, dict[str, str], bytes | None]:
    method = str(request_config.get("method", "GET")).upper()
    raw_url = str(substitute(request_config.get("url") or request_config.get("path") or "/", variables))
    url = raw_url if raw_url.startswith(("http://", "https://")) else urljoin(target.rstrip("/") + "/", raw_url.lstrip("/"))
    if not same_origin(url, target):
        raise ValueError("Le scenario tente de sortir du perimetre de la cible.")
    body, headers = encode_config_body(request_config, variables)
    auth_name = str(request_config.get("auth", "none"))
    if auth_name in auth_map:
        headers.update(auth_map[auth_name])
    return method, url, headers, body


def run_username_enumeration(target: str, config: dict[str, Any], delay: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    section = config.get("username_enumeration", {}) if isinstance(config, dict) else {}
    if not isinstance(section, dict) or not section.get("enabled"):
        return tests, findings
    request_config = section.get("request", {})
    known = str(section.get("known_username", ""))
    unknown = str(section.get("unknown_username") or f"wss-{uuid.uuid4().hex[:10]}@invalid.test")
    wrong_password = str(section.get("wrong_password", "Wss-Wrong-Password-48291!"))
    repetitions = max(1, min(int(section.get("repetitions", 2)), 3))
    if not known or not isinstance(request_config, dict):
        tests.append({"test_id": "username-enum-001", "result": "skipped", "reason": "Configuration incomplete."})
        return tests, findings

    samples: dict[str, list[HttpResult]] = {"known": [], "unknown": []}
    for label, username in (("known", known), ("unknown", unknown)):
        for _ in range(repetitions):
            variables = {"username": username, "password": wrong_password}
            method, url, headers, body = configured_request(target, request_config, variables, {})
            samples[label].append(request_url(method, url, headers, body))
            time.sleep(delay)

    known_result = samples["known"][0]
    unknown_result = samples["unknown"][0]
    similarity = body_similarity(known_result.body, unknown_result.body)
    known_times = [item.elapsed for item in samples["known"]]
    unknown_times = [item.elapsed for item in samples["unknown"]]
    timing_delta = abs(statistics.mean(known_times) - statistics.mean(unknown_times))
    length_a = max(1, len(known_result.body))
    length_b = len(unknown_result.body)
    length_ratio = abs(length_a - length_b) / max(length_a, length_b, 1)
    distinguishable = known_result.status != unknown_result.status or similarity < 0.75 or length_ratio > 0.25 or timing_delta > 0.5
    tests.append({
        "test_id": "username-enum-001",
        "url": redact_url(known_result.url),
        "known_response": response_summary(known_result),
        "unknown_response": response_summary(unknown_result),
        "body_similarity": similarity,
        "length_difference_ratio": round(length_ratio, 4),
        "mean_timing_delta": round(timing_delta, 4),
        "result": "finding" if distinguishable else "passed",
    })
    if distinguishable:
        findings.append(finding(
            "Reponses d'authentification potentiellement enumerables",
            "Broken Authentication",
            "medium",
            "probable",
            f"Compte connu/inconnu : HTTP {known_result.status}/{unknown_result.status}, similarite {similarity:.2f}, ecart de longueur {length_ratio:.2f}.",
            "Les reponses diffèrent suffisamment pour potentiellement reveler l'existence d'un compte. Confirmer manuellement le message visible.",
            "Authentication tests",
        ))
    return tests, findings


def run_rate_limit_test(target: str, config: dict[str, Any], delay: float) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    section = config.get("rate_limit", {}) if isinstance(config, dict) else {}
    if not isinstance(section, dict) or not section.get("enabled"):
        return tests, findings
    request_config = section.get("request", {})
    attempts = max(3, min(int(section.get("attempts", 5)), 10))
    variables = {
        "username": str(section.get("username", f"wss-{uuid.uuid4().hex[:8]}@invalid.test")),
        "password": str(section.get("password", "Wss-Wrong-Password-48291!")),
    }
    responses: list[HttpResult] = []
    for _ in range(attempts):
        method, url, headers, body = configured_request(target, request_config, variables, {})
        responses.append(request_url(method, url, headers, body))
        time.sleep(delay)
    statuses = [item.status for item in responses]
    elapsed = [item.elapsed for item in responses]
    limited = any(status == 429 for status in statuses) or any(status in {403, 423} for status in statuses[2:])
    progressive_delay = len(elapsed) >= 3 and elapsed[-1] > elapsed[0] + 0.75
    result = "passed" if limited or progressive_delay else "finding"
    tests.append({
        "test_id": "rate-limit-001",
        "attempts": attempts,
        "statuses": statuses,
        "elapsed": elapsed,
        "result": result,
    })
    if result == "finding":
        findings.append(finding(
            "Limitation des tentatives non observee",
            "Broken Anti-Automation",
            "low",
            "possible",
            f"{attempts} tentatives controlees : statuts {statuses}; aucun 429/verrouillage/delai progressif net.",
            "Ce test limite ne prouve pas l'absence totale de protection, mais aucun mecanisme visible n'a ete observe.",
            "Authentication tests",
        ))
    return tests, findings


def json_path_get(value: Any, path: str) -> Any:
    current = value
    for token in [part for part in path.split(".") if part]:
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise KeyError(path)
    return current


def evaluate_assertion(assertion: dict[str, Any], results: dict[str, HttpResult]) -> tuple[bool, str]:
    assertion_type = str(assertion.get("type", ""))
    step = str(assertion.get("step", ""))
    left = str(assertion.get("left", step))
    right = str(assertion.get("right", ""))
    if assertion_type == "status_in":
        values = {int(value) for value in assertion.get("values", [])}
        actual = results[step].status
        return actual in values, f"HTTP {actual}, attendu parmi {sorted(values)}"
    if assertion_type == "status_not_in":
        values = {int(value) for value in assertion.get("values", [])}
        actual = results[step].status
        return actual not in values, f"HTTP {actual}, interdit {sorted(values)}"
    if assertion_type == "contains":
        text = str(assertion.get("value", ""))
        return text in results[step].body, f"presence de {text!r}"
    if assertion_type == "not_contains":
        text = str(assertion.get("value", ""))
        return text not in results[step].body, f"absence de {text!r}"
    if assertion_type == "same_status":
        return results[left].status == results[right].status, f"HTTP {results[left].status}/{results[right].status}"
    if assertion_type == "different_status":
        return results[left].status != results[right].status, f"HTTP {results[left].status}/{results[right].status}"
    if assertion_type == "same_body":
        similarity = body_similarity(results[left].body, results[right].body)
        threshold = float(assertion.get("threshold", 0.95))
        return similarity >= threshold, f"similarite {similarity:.2f}, seuil {threshold:.2f}"
    if assertion_type == "different_body":
        similarity = body_similarity(results[left].body, results[right].body)
        threshold = float(assertion.get("threshold", 0.80))
        return similarity < threshold, f"similarite {similarity:.2f}, seuil {threshold:.2f}"
    if assertion_type == "max_elapsed":
        maximum = float(assertion.get("seconds", 2.0))
        return results[step].elapsed <= maximum, f"{results[step].elapsed:.3f}s <= {maximum:.3f}s"
    raise ValueError(f"Assertion non supportee : {assertion_type}")


def run_business_scenarios(
    target: str,
    config: dict[str, Any],
    auth_map: dict[str, dict[str, str]],
    delay: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    tests: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    scenarios = config.get("scenarios", []) if isinstance(config, dict) else []
    for scenario in scenarios:
        if not isinstance(scenario, dict) or not scenario.get("enabled", False):
            continue
        scenario_id = str(scenario.get("id") or f"scenario-{len(tests)+1:03d}")
        log(f"Scenario metier : {scenario.get('name', scenario_id)}")
        variables = {str(k): v for k, v in scenario.get("variables", {}).items()}
        results: dict[str, HttpResult] = {}
        step_records: list[dict[str, Any]] = []
        scenario_error = ""
        try:
            for step in scenario.get("steps", []):
                step_id = str(step.get("id") or f"step-{len(step_records)+1}")
                if "repeat_of" in step:
                    source = str(step["repeat_of"])
                    source_config = next(item for item in scenario.get("steps", []) if str(item.get("id")) == source)
                    request_config = copy.deepcopy(source_config.get("request", source_config))
                else:
                    request_config = step.get("request", step)
                method, url, headers, body = configured_request(target, request_config, variables, auth_map)
                result = request_url(method, url, headers, body)
                results[step_id] = result
                step_records.append({
                    "step": step_id,
                    "method": method,
                    "url": redact_url(url),
                    "response": response_summary(result),
                })
                for capture in step.get("capture", []):
                    name = str(capture.get("name", ""))
                    path = str(capture.get("json_path", ""))
                    if name and path:
                        payload = json.loads(result.body)
                        variables[name] = json_path_get(payload, path)
                time.sleep(delay)
        except (ValueError, KeyError, StopIteration, json.JSONDecodeError) as error:
            scenario_error = str(error)

        assertions: list[dict[str, Any]] = []
        failed = False
        if not scenario_error:
            for assertion in scenario.get("assertions", []):
                try:
                    passed, detail = evaluate_assertion(assertion, results)
                except (ValueError, KeyError) as error:
                    passed, detail = False, str(error)
                assertions.append({"type": assertion.get("type"), "passed": passed, "detail": detail})
                if not passed:
                    failed = True
        result_label = "error" if scenario_error else ("finding" if failed else "passed")
        tests.append({
            "scenario_id": scenario_id,
            "name": scenario.get("name", scenario_id),
            "description": scenario.get("description", ""),
            "steps": step_records,
            "assertions": assertions,
            "result": result_label,
            "error": scenario_error or None,
        })
        if failed:
            metadata = scenario.get("finding", {})
            findings.append(finding(
                str(metadata.get("title", f"Scenario metier en echec : {scenario.get('name', scenario_id)}")),
                str(metadata.get("category", "Business Logic")),
                str(metadata.get("severity", "medium")),
                str(metadata.get("confidence", "probable")),
                "; ".join(item["detail"] for item in assertions if not item["passed"])[:1000],
                str(metadata.get("description", scenario.get("description", "Le comportement observe ne respecte pas les assertions de securite configurees."))),
                "Business logic scenarios",
            ))
    return tests, findings


def deduplicate_findings(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item.get("title", "")).lower(),
            str(item.get("category", "")).lower(),
            str(item.get("evidence", ""))[:200].lower(),
        )
        if key not in merged or SEVERITY_ORDER.get(str(item.get("severity", "info")), 9) < SEVERITY_ORDER.get(str(merged[key].get("severity", "info")), 9):
            merged[key] = item
    return sorted(merged.values(), key=lambda item: (SEVERITY_ORDER.get(str(item.get("severity", "info")), 9), str(item.get("title", ""))))


def main() -> None:
    parser = argparse.ArgumentParser(description="Tests d'authentification, session, controle d'acces et logique metier")
    parser.add_argument("--target", required=True)
    parser.add_argument("--auth-output", required=True, type=Path)
    parser.add_argument("--access-output", required=True, type=Path)
    parser.add_argument("--logic-output", required=True, type=Path)
    parser.add_argument("--har-user-a", type=Path)
    parser.add_argument("--har-user-b", type=Path)
    parser.add_argument("--auth-config", type=Path)
    parser.add_argument("--scenario-config", type=Path)
    parser.add_argument("--auth-tests", action="store_true")
    parser.add_argument("--session-tests", action="store_true")
    parser.add_argument("--access-tests", action="store_true")
    parser.add_argument("--business-tests", action="store_true")
    parser.add_argument("--max-access-tests", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.2)
    args = parser.parse_args()

    for directory in (args.auth_output, args.access_output, args.logic_output):
        directory.mkdir(parents=True, exist_ok=True)

    user_a = load_har(args.har_user_a, args.target) if args.har_user_a else []
    user_b = load_har(args.har_user_b, args.target) if args.har_user_b else []
    config = read_json(args.auth_config, {}) if args.auth_config else {}
    scenarios = read_json(args.scenario_config, {}) if args.scenario_config else {}

    auth_tests: list[dict[str, Any]] = []
    auth_findings: list[dict[str, Any]] = []
    access_tests: list[dict[str, Any]] = []
    access_findings: list[dict[str, Any]] = []
    logic_tests: list[dict[str, Any]] = []
    logic_findings: list[dict[str, Any]] = []

    if args.auth_tests:
        tests, findings = run_username_enumeration(args.target, config, args.delay)
        auth_tests.extend(tests)
        auth_findings.extend(findings)
        tests, findings = run_rate_limit_test(args.target, config, args.delay)
        auth_tests.extend(tests)
        auth_findings.extend(findings)

    if args.session_tests:
        tests, findings = run_session_test(user_a, args.delay)
        auth_tests.extend(tests)
        auth_findings.extend(findings)

    if args.access_tests:
        tests, findings = run_access_tests(
            args.target,
            user_a,
            user_b,
            max(1, min(args.max_access_tests, 25)),
            max(0.0, args.delay),
        )
        access_tests.extend(tests)
        access_findings.extend(findings)

    if args.business_tests:
        auth_map = {
            "user_a": auth_headers(user_a),
            "user_b": auth_headers(user_b),
            "none": {},
        }
        tests, findings = run_business_scenarios(args.target, scenarios, auth_map, args.delay)
        logic_tests.extend(tests)
        logic_findings.extend(findings)

    write_json(args.auth_output / "authentication-tests.json", auth_tests)
    write_json(args.auth_output / "authentication-findings.json", deduplicate_findings(auth_findings))
    write_json(args.access_output / "access-control-tests.json", access_tests)
    write_json(args.access_output / "access-control-findings.json", deduplicate_findings(access_findings))
    write_json(args.logic_output / "business-logic-tests.json", logic_tests)
    write_json(args.logic_output / "business-logic-findings.json", deduplicate_findings(logic_findings))
    write_json(args.auth_output / "auth-input-summary.json", {
        "user_a_request_count": len(user_a),
        "user_b_request_count": len(user_b),
        "user_a_auth_detected": bool(auth_headers(user_a)),
        "user_b_auth_detected": bool(auth_headers(user_b)),
        "auth_config_loaded": bool(config),
        "scenario_config_loaded": bool(scenarios),
    })

    log_ok(
        f"Tests auth={len(auth_tests)}, acces={len(access_tests)}, logique={len(logic_tests)}; "
        f"constats={len(auth_findings)+len(access_findings)+len(logic_findings)}"
    )


if __name__ == "__main__":
    main()
