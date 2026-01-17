"""CSPBUILDER MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from cspbuilder.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-cspbuilder[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-cspbuilder[mcp]'")
        return 1
    app = FastMCP("cspbuilder")

    @app.tool()
    def cspbuilder_scan(target: str) -> str:
        """Generate and audit a Content-Security-Policy from a page's resources. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
