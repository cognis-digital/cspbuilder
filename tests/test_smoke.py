"""Smoke tests for CSPBUILDER. No network. Run with `python -m pytest` or unittest."""
import io
import os
import sys
import json
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspbuilder import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    extract_resources,
    build_policy,
    audit_policy,
    parse_policy,
    policy_to_header,
)
from cspbuilder.cli import main  # noqa: E402

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "sample_page.html",
)

SAMPLE_HTML = """
<html><head>
<link rel="stylesheet" href="https://fonts.googleapis.com/x.css">
<style>.a{background:url('https://cdn.x.com/a.png')}</style>
</head><body>
<img src="/logo.png"><img src="https://img.cdn.net/b.jpg">
<iframe src="https://frame.x.com/w"></iframe>
<script src="https://cdn.jsdelivr.net/c.js"></script>
<script>fetch("https://api.x.com/v1");var w=new WebSocket("wss://s.x.com/l");</script>
<button onclick="go()">x</button>
</body></html>
"""


class TestMeta(unittest.TestCase):
    def test_constants(self):
        self.assertEqual(TOOL_NAME, "cspbuilder")
        self.assertTrue(TOOL_VERSION)


class TestExtract(unittest.TestCase):
    def test_scan_collapses_self_and_finds_origins(self):
        scan = extract_resources(SAMPLE_HTML, "https://app.x.com")
        self.assertIn("'self'", scan.sources["img-src"])
        self.assertIn("https://img.cdn.net", scan.sources["img-src"])
        self.assertIn("https://cdn.jsdelivr.net", scan.sources["script-src"])
        self.assertIn("https://fonts.googleapis.com", scan.sources["style-src"])
        self.assertIn("https://frame.x.com", scan.sources["frame-src"])
        self.assertIn("https://cdn.x.com", scan.sources["img-src"])
        self.assertIn("https://api.x.com", scan.sources["connect-src"])
        self.assertIn("wss://s.x.com", scan.sources["connect-src"])
        self.assertTrue(scan.has_inline_script)
        self.assertTrue(scan.has_inline_style)
        self.assertTrue(scan.has_inline_handlers)


class TestBuild(unittest.TestCase):
    def test_build_is_locked_by_default(self):
        scan = extract_resources(SAMPLE_HTML, "https://app.x.com")
        policy = build_policy(scan, allow_inline=False)
        self.assertEqual(policy["default-src"], ["'self'"])
        self.assertEqual(policy["object-src"], ["'none'"])
        self.assertEqual(policy["base-uri"], ["'self'"])
        self.assertEqual(policy["frame-ancestors"], ["'self'"])
        self.assertNotIn("'unsafe-inline'", policy["script-src"])
        header = policy_to_header(policy)
        self.assertIn("script-src", header)
        self.assertIn("https://cdn.jsdelivr.net", header)

    def test_allow_inline_adds_unsafe_inline(self):
        scan = extract_resources(SAMPLE_HTML, "https://app.x.com")
        policy = build_policy(scan, allow_inline=True)
        self.assertIn("'unsafe-inline'", policy["script-src"])


class TestAudit(unittest.TestCase):
    def test_weak_policy_flags_high(self):
        policy = parse_policy(
            "default-src *; script-src 'unsafe-inline' 'unsafe-eval' https:")
        findings = audit_policy(policy)
        sevs = {f.severity for f in findings}
        self.assertIn("high", sevs)
        msgs = " ".join(f.message for f in findings)
        self.assertIn("unsafe-inline", msgs.lower())
        self.assertIn("unsafe-eval", msgs.lower())

    def test_clean_policy_is_info_only(self):
        policy = parse_policy(
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'self'; form-action 'self'")
        findings = audit_policy(policy)
        self.assertTrue(all(f.severity == "info" for f in findings))

    def test_nonce_downgrades_unsafe_inline(self):
        policy = parse_policy("script-src 'unsafe-inline' 'nonce-abc123'")
        findings = audit_policy(policy)
        ui = [f for f in findings if f.value == "'unsafe-inline'"]
        self.assertTrue(ui and ui[0].severity == "low")


class TestCLI(unittest.TestCase):
    def test_build_json_exit_and_payload(self):
        if not os.path.exists(DEMO):
            self.skipTest("demo file missing")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "build", DEMO, "--url", "https://app.acme.com"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["command"], "build")
        self.assertIn("script-src", data["policy"])
        self.assertEqual(rc, 1)  # demo has inline content -> warnings -> non-zero

    def test_audit_weak_exit_one(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "audit",
                       "--policy", "default-src *; script-src 'unsafe-eval'"])
        self.assertEqual(rc, 1)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["counts"]["high"] >= 1)

    def test_audit_clean_exit_zero(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["audit", "--policy",
                       "default-src 'self'; object-src 'none'; base-uri 'self'; "
                       "frame-ancestors 'self'; form-action 'self'"])
        self.assertEqual(rc, 0)

    def test_usage_error_exit_two(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["audit"])  # no policy/file
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
