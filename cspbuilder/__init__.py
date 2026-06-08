"""CSPBUILDER — generate and audit a Content-Security-Policy from page resources.

Defensive / authorized-testing tool. Analysis, generation, and detection only.
No unauthorized attack capability.
"""
from .core import (
    Finding,
    Severity,
    extract_resources,
    build_policy,
    audit_policy,
    parse_policy,
    policy_to_header,
    GENERATABLE_DIRECTIVES,
)

TOOL_NAME = "cspbuilder"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "Severity",
    "extract_resources",
    "build_policy",
    "audit_policy",
    "parse_policy",
    "policy_to_header",
    "GENERATABLE_DIRECTIVES",
]
