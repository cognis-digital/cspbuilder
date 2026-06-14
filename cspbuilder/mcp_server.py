"""CSPBUILDER MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from cspbuilder.core import (
    extract_resources,
    build_policy,
    audit_policy,
    policy_to_header,
)


def _scan_to_json(html: str, page_url: str = "") -> str:
    """Scan *html* and return a JSON string with the generated policy and findings."""
    scan_result = extract_resources(html, page_url)
    policy = build_policy(scan_result)
    findings = audit_policy(policy)
    return json.dumps(
        {
            "header": policy_to_header(policy),
            "policy": policy,
            "findings": [f.to_dict() for f in findings],
        },
        indent=2,
    )


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cspbuilder[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP  # type: ignore[import]
    except Exception:
        print("Install the MCP extra: pip install 'cognis-cspbuilder[mcp]'")
        return 1
    app = FastMCP("cspbuilder")

    @app.tool()
    def cspbuilder_scan(html: str, page_url: str = "") -> str:
        """Generate and audit a Content-Security-Policy from HTML content.

        Returns JSON with the generated policy header and audit findings.
        """
        return _scan_to_json(html, page_url)

    app.run()
    return 0
