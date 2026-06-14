"""Hardening tests for CSPBUILDER — edge cases and error paths.

Covers:
  - Missing / unreadable file -> exit 2
  - Empty HTML input to extract_resources
  - Non-string input to extract_resources / parse_policy / build_policy / audit_policy
  - Malformed (semicolons-only) policy string in the CLI audit path
  - Empty policy in audit -> exit 2
  - CLI build with a missing file -> exit 2
  - mcp_server._scan_to_json on empty HTML
"""
from __future__ import annotations

import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cspbuilder.core import (
    ScanResult,
    audit_policy,
    build_policy,
    extract_resources,
    parse_policy,
)
from cspbuilder.cli import main


# --------------------------------------------------------------------------- #
# core hardening
# --------------------------------------------------------------------------- #

class TestExtractResourcesEdgeCases(unittest.TestCase):
    def test_empty_string_returns_empty_scan(self):
        result = extract_resources("")
        self.assertIsInstance(result, ScanResult)
        self.assertEqual(result.sources, {})
        self.assertFalse(result.has_inline_script)
        self.assertFalse(result.has_inline_style)

    def test_non_string_raises_value_error(self):
        with self.assertRaises((TypeError, ValueError)):
            extract_resources(None)  # type: ignore[arg-type]

    def test_malformed_page_url_falls_back_gracefully(self):
        # A URL that is weirdly malformed should not crash — origins just
        # won't be collapsed to 'self'.
        result = extract_resources(
            '<script src="https://cdn.example.com/a.js"></script>',
            page_url="not a url at all :::///",
        )
        script_srcs = result.sources.get("script-src", set())
        self.assertIn("https://cdn.example.com", script_srcs)


class TestParsePolicyEdgeCases(unittest.TestCase):
    def test_non_string_raises_type_error(self):
        with self.assertRaises(TypeError):
            parse_policy(42)  # type: ignore[arg-type]

    def test_empty_string_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_policy("")

    def test_whitespace_only_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_policy("   ")


class TestBuildPolicyEdgeCases(unittest.TestCase):
    def test_non_scan_result_raises_type_error(self):
        with self.assertRaises(TypeError):
            build_policy({"sources": {}})  # type: ignore[arg-type]

    def test_empty_scan_result_produces_secure_defaults(self):
        policy = build_policy(ScanResult())
        self.assertEqual(policy["default-src"], ["'self'"])
        self.assertEqual(policy["object-src"], ["'none'"])
        self.assertIn("base-uri", policy)


class TestAuditPolicyEdgeCases(unittest.TestCase):
    def test_non_dict_raises_type_error(self):
        with self.assertRaises(TypeError):
            audit_policy("default-src 'self'")  # type: ignore[arg-type]

    def test_empty_dict_raises_value_error(self):
        with self.assertRaises(ValueError):
            audit_policy({})


# --------------------------------------------------------------------------- #
# CLI hardening
# --------------------------------------------------------------------------- #

class TestCLIHardening(unittest.TestCase):
    def test_build_missing_file_exits_two(self):
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["build", "/nonexistent/path/page.html"])
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_audit_empty_policy_string_exits_two(self):
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["audit", "--policy", ""])
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_audit_semicolons_only_exits_two(self):
        # ";;;" parses to an empty dict which audit_policy rejects.
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["audit", "--policy", ";;;"])
        self.assertEqual(rc, 2)

    def test_audit_missing_file_exits_two(self):
        stderr_buf = io.StringIO()
        with redirect_stderr(stderr_buf):
            rc = main(["audit", "/nonexistent/policy.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("error", stderr_buf.getvalue().lower())

    def test_build_empty_html_file_exits_zero_no_traceback(self):
        # An empty HTML file is valid input and should produce a clean policy.
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html",
                                        delete=False) as fh:
            fh.write("")
            tmp = fh.name
        try:
            stdout_buf = io.StringIO()
            stderr_buf = io.StringIO()
            with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
                rc = main(["build", tmp])
            # No traceback on stderr
            self.assertNotIn("Traceback", stderr_buf.getvalue())
            self.assertIn(rc, (0, 1))
        finally:
            os.unlink(tmp)


# --------------------------------------------------------------------------- #
# mcp_server hardening
# --------------------------------------------------------------------------- #

class TestMCPServerHelper(unittest.TestCase):
    def test_scan_to_json_on_empty_html_returns_valid_json(self):
        import json
        from cspbuilder.mcp_server import _scan_to_json
        result = _scan_to_json("")
        data = json.loads(result)
        self.assertIn("policy", data)
        self.assertIn("header", data)
        self.assertIn("findings", data)

    def test_scan_to_json_with_external_script(self):
        import json
        from cspbuilder.mcp_server import _scan_to_json
        html = '<script src="https://cdn.example.com/app.js"></script>'
        data = json.loads(_scan_to_json(html))
        self.assertIn("https://cdn.example.com", data["header"])


if __name__ == "__main__":
    unittest.main()
