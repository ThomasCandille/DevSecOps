#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import discovery  # noqa: E402
import har_active  # noqa: E402
import report as report_module  # noqa: E402


class UrlEncodingTests(unittest.TestCase):
    def test_unicode_url_is_encoded(self) -> None:
        value = discovery.encode_url_for_request(
            "http://127.0.0.1:3000/préférences?q=café"
        )
        self.assertEqual(
            value,
            "http://127.0.0.1:3000/pr%C3%A9f%C3%A9rences?q=caf%C3%A9",
        )

    def test_existing_percent_encoding_is_preserved(self) -> None:
        value = discovery.encode_url_for_request(
            "http://127.0.0.1:3000/search?q=the%20vert"
        )
        self.assertIn("q=the%20vert", value)


class JavaScriptDiscoveryTests(unittest.TestCase):
    def test_only_contextual_routes_are_kept(self) -> None:
        endpoints: list[dict] = []
        parameters: list[dict] = []
        findings: list[dict] = []
        content = '''
          const labels = {x: "/}},B0={selkiesLogoAlt:"};
          fetch("/api/users?id=42");
          const routes = [{path: "administration"}];
        '''
        discovery.extract_routes_from_js(
            target="http://127.0.0.1:3000",
            source_name="test.js",
            content=content,
            endpoints=endpoints,
            parameters=parameters,
            findings=findings,
            add_finding=lambda *args, **kwargs: None,
        )
        paths = {item["path"] for item in endpoints}
        self.assertIn("/api/users?id=42", paths)
        self.assertTrue(any("administration" in path for path in paths))
        self.assertFalse(any("selkiesLogoAlt" in path for path in paths))


class HarTests(unittest.TestCase):
    def test_same_origin_filter(self) -> None:
        self.assertTrue(har_active.same_origin(
            "http://127.0.0.1:3000/api", "http://127.0.0.1:3000"
        ))
        self.assertFalse(har_active.same_origin(
            "http://127.0.0.1:4000/api", "http://127.0.0.1:3000"
        ))


class ReportTests(unittest.TestCase):
    def test_report_generation_with_empty_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in (
                "00-meta", "02-static", "03-dynamic", "04-authentication",
                "05-access-control", "06-business-logic", "07-zap",
            ):
                (root / name).mkdir(parents=True)
            (root / "00-meta/scan.json").write_text(
                json.dumps({"target": "http://127.0.0.1:3000", "scan_id": "test", "mode": "passive"}),
                encoding="utf-8",
            )
            report_data = report_module.build_report(root)
            html = report_module.render_html(report_data)
            self.assertIn("http://127.0.0.1:3000", html)
            self.assertIn("Evaluation de securite", html)


if __name__ == "__main__":
    unittest.main()
