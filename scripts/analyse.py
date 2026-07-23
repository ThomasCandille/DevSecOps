#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

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


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


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
    content = read_text(directory / "headers.txt")
    if not content:
        return

    blocks = [block for block in re.split(r"\r?\n\r?\n", content) if block.strip()]
    final_block = blocks[-1] if blocks else content
    headers: dict[str, str] = {}

    for line in final_block.splitlines()[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()

    for name, (title, severity, description) in SECURITY_HEADERS.items():
        if name not in headers:
            add_finding(
                findings,
                title=title,
                category="Security Misconfiguration",
                severity=severity,
                confidence="confirmed",
                tool="HTTP headers",
                evidence=f"En-tete {name} absent de la reponse finale.",
                description=description,
            )

    server = headers.get("server")
    if server:
        add_finding(
            findings,
            title="Technologie serveur exposee",
            category="Information Disclosure",
            severity="info",
            confidence="confirmed",
            tool="HTTP headers",
            evidence=f"Server: {server}",
            description="L'en-tete Server fournit une information utile a la reconnaissance.",
        )


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
        path, status = match.groups()
        severity = "low" if path in {"files", "src", "/files", "/src"} else "info"
        add_finding(
            findings,
            title=f"Ressource decouverte : /{path.lstrip('/')}",
            category="Content Discovery",
            severity=severity,
            confidence="confirmed",
            tool="Gobuster",
            evidence=f"{line.strip()}",
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
                title="En-tete de securite manquant signale par Nikto",
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


def deduplicate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    fingerprints: set[tuple[str, str]] = set()

    for finding in findings:
        fingerprint = (finding["title"], finding["evidence"].lower())
        if fingerprint not in fingerprints:
            fingerprints.add(fingerprint)
            unique.append(finding)

    return unique


def write_markdown(target: str, directory: Path, findings: list[dict[str, Any]]) -> None:
    status_content = read_text(directory / "tool-status.tsv")
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

    for line in status_content.splitlines()[1:]:
        if "\t" in line:
            tool, status = line.split("\t", 1)
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

    lines.extend(
        [
            "## Limite du MVP",
            "",
            "Ce scan couvre la reconnaissance et quelques mauvaises configurations. "
            "Il ne confirme pas encore les injections, XSS, failles d'authentification "
            "ou defauts de controle d'acces.",
            "",
        ]
    )

    (directory / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyse les sorties du scanner MVP.")
    parser.add_argument("--target", required=True)
    parser.add_argument("--input", required=True, type=Path)
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    analyse_headers(args.input, findings)
    analyse_nmap(args.input, findings)
    analyse_gobuster(args.input, findings)
    analyse_nikto(args.input, findings)
    findings = deduplicate(findings)

    payload = {
        "target": args.target,
        "finding_count": len(findings),
        "findings": findings,
    }

    (args.input / "report.json").write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    write_markdown(args.target, args.input, findings)

    print(f"Rapports generes : {args.input / 'report.md'} et report.json")


if __name__ == "__main__":
    main()
