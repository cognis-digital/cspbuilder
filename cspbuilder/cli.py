"""CSPBUILDER command-line interface.

Subcommands:
  build  PAGE.html [--url ORIGIN] [--allow-inline]
         Scan an HTML page and emit a least-privilege CSP.
  audit  [POLICY_FILE | --policy "csp string"]
         Parse an existing CSP and report weaknesses.

Common flags: --version, --format {table,json}

Exit codes:
  0  success, no actionable findings
  1  audit found HIGH/MEDIUM weaknesses, or build produced a policy that
     still permits inline content (--allow-inline)
  2  usage / input error
"""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Severity,
    extract_resources,
    build_policy,
    audit_policy,
    parse_policy,
    policy_to_header,
)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _emit(payload: dict, fmt: str, table_renderer) -> None:
    if fmt == "json":
        print(json.dumps(payload, indent=2, sort_keys=False))
    else:
        table_renderer(payload)


def _cmd_build(args) -> int:
    try:
        html = _read(args.page)
    except OSError as exc:
        print(f"error: cannot read {args.page}: {exc}", file=sys.stderr)
        return 2

    scan = extract_resources(html, args.url)
    policy = build_policy(scan, allow_inline=args.allow_inline)
    header = policy_to_header(policy)

    warnings = []
    if args.allow_inline and (scan.has_inline_script or scan.has_inline_style
                              or scan.has_inline_handlers):
        warnings.append("Policy uses 'unsafe-inline'; refactor to nonces/hashes.")
    if scan.has_eval_hint:
        warnings.append("Inline eval()/new Function() detected; CSP will block it.")
    if scan.has_inline_handlers:
        warnings.append("Inline on*= event handlers detected; CSP will block them "
                        "unless refactored.")

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "command": "build",
        "page": args.page,
        "header": header,
        "policy": policy,
        "observed": {k: sorted(v) for k, v in scan.sources.items()},
        "inline_script": scan.has_inline_script,
        "inline_style": scan.has_inline_style,
        "inline_handlers": scan.has_inline_handlers,
        "warnings": warnings,
    }

    def render(p):
        print(f"{TOOL_NAME} {TOOL_VERSION} — generated Content-Security-Policy")
        print("=" * 60)
        for directive, sources in p["policy"].items():
            print(f"  {directive}: {' '.join(sources)}")
        print("-" * 60)
        print("Header:")
        print(f"  Content-Security-Policy: {p['header']}")
        if p["warnings"]:
            print("-" * 60)
            print("Warnings:")
            for w in p["warnings"]:
                print(f"  ! {w}")

    _emit(payload, args.format, render)
    # Non-zero only when the emitted policy is not fully locked-down.
    return 1 if warnings else 0


def _cmd_audit(args) -> int:
    if args.policy is not None:
        header = args.policy
    elif args.policy_file:
        try:
            header = _read(args.policy_file)
        except OSError as exc:
            print(f"error: cannot read {args.policy_file}: {exc}", file=sys.stderr)
            return 2
    else:
        print('error: provide a POLICY_FILE or --policy "..."', file=sys.stderr)
        return 2

    header = header.strip()
    if not header:
        print("error: empty policy", file=sys.stderr)
        return 2

    policy = parse_policy(header)
    findings = audit_policy(policy)
    counts = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0, Severity.INFO: 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    payload = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "command": "audit",
        "policy": policy,
        "counts": counts,
        "findings": [f.to_dict() for f in findings],
    }

    def render(p):
        print(f"{TOOL_NAME} {TOOL_VERSION} — CSP audit")
        print("=" * 60)
        for f in p["findings"]:
            tag = f["severity"].upper().ljust(6)
            val = f" [{f['value']}]" if f["value"] else ""
            print(f"  {tag} {f['directive']}{val}: {f['message']}")
        print("-" * 60)
        c = p["counts"]
        print(f"  high={c.get('high',0)} medium={c.get('medium',0)} "
              f"low={c.get('low',0)} info={c.get('info',0)}")

    _emit(payload, args.format, render)
    return 1 if (counts.get(Severity.HIGH, 0) or counts.get(Severity.MEDIUM, 0)) else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate and audit a Content-Security-Policy from page resources.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="output format (default: table)")

    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="scan an HTML page and emit a least-privilege CSP")
    b.add_argument("page", help="path to an HTML file")
    b.add_argument("--url", default="", help="page origin (e.g. https://app.example.com) "
                                             "so same-origin sources collapse to 'self'")
    b.add_argument("--allow-inline", action="store_true",
                   help="permit 'unsafe-inline' for inline script/style (not recommended)")
    b.set_defaults(func=_cmd_build)

    a = sub.add_parser("audit", help="audit an existing CSP for weaknesses")
    a.add_argument("policy_file", nargs="?", help="path to a file containing a CSP header")
    a.add_argument("--policy", default=None, help="CSP header string to audit directly")
    a.set_defaults(func=_cmd_audit)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
