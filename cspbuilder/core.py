"""CSPBUILDER core engine.

Two real capabilities, standard library only:

  1. BUILD  — scan an HTML page for the resources it actually loads
              (scripts, styles, images, frames, fonts, connect/XHR hints,
              inline handlers) and emit a *least-privilege* Content-Security-Policy
              that would allow exactly those origins.

  2. AUDIT  — parse an existing CSP string/header and report weaknesses
              (missing key directives, 'unsafe-inline'/'unsafe-eval',
              wildcard sources, missing object-src/base-uri, data: in script-src,
              over-broad default-src, etc.) in the spirit of csp-evaluator.

Everything here is deterministic and offline. No network access.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse


# --------------------------------------------------------------------------- #
# Findings model
# --------------------------------------------------------------------------- #
class Severity:
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}


@dataclass
class Finding:
    directive: str
    severity: str
    message: str
    value: str = ""

    def to_dict(self) -> dict:
        return {
            "directive": self.directive,
            "severity": self.severity,
            "message": self.message,
            "value": self.value,
        }


# Directives CSPBUILDER will generate from scanned resources.
GENERATABLE_DIRECTIVES = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "font-src",
    "connect-src",
    "frame-src",
    "media-src",
    "object-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
]

# Map HTML element -> CSP directive it feeds.
_TAG_DIRECTIVE = {
    "script": "script-src",
    "link_style": "style-src",
    "style": "style-src",
    "img": "img-src",
    "image": "img-src",
    "iframe": "frame-src",
    "frame": "frame-src",
    "audio": "media-src",
    "video": "media-src",
    "source": "media-src",
    "object": "object-src",
    "embed": "object-src",
    "form": "form-action",
}

# Attributes that carry a fetched URL, per tag.
_URL_ATTRS = {
    "script": ["src"],
    "img": ["src", "srcset"],
    "image": ["src", "href"],
    "iframe": ["src"],
    "frame": ["src"],
    "audio": ["src"],
    "video": ["src", "poster"],
    "source": ["src", "srcset"],
    "object": ["data"],
    "embed": ["src"],
    "form": ["action"],
    "a": [],  # ignored
}

_INLINE_HANDLER_RE = re.compile(r"^on[a-z]+$")
_CSS_URL_RE = re.compile(r"url\(\s*['\"]?([^'\")]+)['\"]?\s*\)", re.I)
_FONT_EXT_RE = re.compile(r"\.(woff2?|ttf|otf|eot)(\?|#|$)", re.I)


@dataclass
class ScanResult:
    # directive -> set of source expressions
    sources: dict = field(default_factory=dict)
    has_inline_script: bool = False
    has_inline_style: bool = False
    has_inline_handlers: bool = False
    has_eval_hint: bool = False
    notes: list = field(default_factory=list)


# --------------------------------------------------------------------------- #
# HTML scanning
# --------------------------------------------------------------------------- #
class _ResourceParser(HTMLParser):
    def __init__(self, page_origin: str):
        super().__init__(convert_charrefs=True)
        self.page_origin = page_origin
        self.result = ScanResult()
        self._in_script = False
        self._in_style = False
        self._script_is_external = False
        self._script_buf = []
        self._style_buf = []

    # -- helpers ----------------------------------------------------------- #
    def _add(self, directive: str, url: str):
        src = self._origin_of(url)
        if not src:
            return
        self.result.sources.setdefault(directive, set()).add(src)

    def _origin_of(self, url: str):
        """Reduce a URL to a CSP source expression (scheme://host[:port])."""
        url = (url or "").strip()
        if not url:
            return None
        low = url.lower()
        if low.startswith("data:"):
            return "data:"
        if low.startswith("blob:"):
            return "blob:"
        if low.startswith("javascript:") or low.startswith("mailto:") or low.startswith("tel:"):
            return None
        if url.startswith("//"):
            url = "https:" + url
        parsed = urlparse(url)
        if not parsed.netloc:
            # relative URL -> same origin
            return "'self'"
        scheme = parsed.scheme or "https"
        host = parsed.hostname or ""
        if not host:
            return "'self'"
        netloc = host
        if parsed.port:
            netloc = f"{host}:{parsed.port}"
        src = f"{scheme}://{netloc}"
        if self.page_origin and src == self.page_origin:
            return "'self'"
        return src

    @staticmethod
    def _split_srcset(value: str):
        out = []
        for part in value.split(","):
            cand = part.strip().split()
            if cand:
                out.append(cand[0])
        return out

    # -- parser hooks ------------------------------------------------------ #
    def handle_starttag(self, tag, attrs):
        adict = {k.lower(): (v or "") for k, v in attrs}

        # inline event handlers (onclick=, etc.)
        for k in adict:
            if _INLINE_HANDLER_RE.match(k):
                self.result.has_inline_handlers = True
                break

        if tag == "link":
            rel = adict.get("rel", "").lower()
            href = adict.get("href", "")
            if "stylesheet" in rel:
                self._add("style-src", href)
            elif "preconnect" in rel or "dns-prefetch" in rel:
                self._add("connect-src", href)
            elif "icon" in rel or "apple-touch-icon" in rel:
                self._add("img-src", href)
            elif "preload" in rel:
                as_ = adict.get("as", "").lower()
                d = {"script": "script-src", "style": "style-src",
                     "font": "font-src", "image": "img-src"}.get(as_, "default-src")
                self._add(d, href)
            return

        if tag == "script":
            self._in_script = True
            self._script_buf = []
            src = adict.get("src", "")
            if src:
                self._script_is_external = True
                self._add("script-src", src)
            else:
                self._script_is_external = False
            return

        if tag == "style":
            self._in_style = True
            self._style_buf = []
            return

        # base href affects base-uri risk surface
        if tag == "base":
            self.result.notes.append("page sets <base>; base-uri should be locked")

        directive = _TAG_DIRECTIVE.get(tag)
        if directive:
            for attr in _URL_ATTRS.get(tag, []):
                val = adict.get(attr, "")
                if not val:
                    continue
                if attr == "srcset":
                    for u in self._split_srcset(val):
                        self._add(directive, u)
                else:
                    self._add(directive, val)
                    # font heuristic: <source>/<link> to a font file
                    if _FONT_EXT_RE.search(val):
                        self._add("font-src", val)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script" and self._in_script:
            self._in_script = False
            body = "".join(self._script_buf)
            if not self._script_is_external and body.strip():
                self.result.has_inline_script = True
                if re.search(r"\b(eval|new\s+Function|setTimeout\s*\(\s*['\"])", body):
                    self.result.has_eval_hint = True
                # connect-src hints from inline fetch/XHR/WebSocket
                for m in re.finditer(
                    r"""(?:fetch|open|WebSocket|EventSource)\s*\(\s*['\"]([^'\"]+)['\"]""",
                    body,
                ):
                    self._add("connect-src", m.group(1))
        elif tag == "style" and self._in_style:
            self._in_style = False
            css = "".join(self._style_buf)
            if css.strip():
                self.result.has_inline_style = True
            for m in _CSS_URL_RE.finditer(css):
                url = m.group(1)
                directive = "font-src" if _FONT_EXT_RE.search(url) else "img-src"
                self._add(directive, url)

    def handle_data(self, data):
        if self._in_script:
            self._script_buf.append(data)
        elif self._in_style:
            self._style_buf.append(data)


def extract_resources(html: str, page_url: str = "") -> ScanResult:
    """Scan HTML and return a ScanResult describing referenced origins.

    Accepts an empty string (returns an empty ScanResult). Raises ValueError
    on non-string input.
    """
    if not isinstance(html, str):
        raise ValueError(
            f"extract_resources: html must be a str, got {type(html).__name__}"
        )
    page_url = page_url or ""
    origin = ""
    if page_url:
        try:
            p = urlparse(page_url)
            if p.scheme and p.hostname:
                netloc = p.hostname + (f":{p.port}" if p.port else "")
                origin = f"{p.scheme}://{netloc}"
        except Exception:
            # Malformed page_url — treat as no origin (safe fallback)
            origin = ""
    resource_parser = _ResourceParser(origin)
    try:
        resource_parser.feed(html)
        resource_parser.close()
    except Exception as exc:
        raise ValueError(f"extract_resources: HTML parsing failed: {exc}") from exc
    return resource_parser.result


# --------------------------------------------------------------------------- #
# Policy building (least privilege)
# --------------------------------------------------------------------------- #
def build_policy(scan: ScanResult, allow_inline: bool = False) -> dict:
    """Produce an ordered {directive: [sources]} CSP from a scan.

    Secure-by-default: default-src 'self', object-src 'none', base-uri 'self',
    frame-ancestors 'self', plus exactly the origins observed. Inline content is
    NOT permitted unless allow_inline=True (and even then a warning is attached).

    Raises TypeError if *scan* is not a ScanResult.
    """
    if not isinstance(scan, ScanResult):
        raise TypeError(
            f"build_policy: expected ScanResult, got {type(scan).__name__}"
        )
    policy: dict = {}

    # Baseline hardening directives.
    policy["default-src"] = ["'self'"]
    policy["object-src"] = ["'none'"]
    policy["base-uri"] = ["'self'"]
    policy["frame-ancestors"] = ["'self'"]
    policy["form-action"] = ["'self'"]

    for directive in GENERATABLE_DIRECTIVES:
        if directive in policy:
            srcs = set(policy[directive])
        else:
            srcs = set()
        observed = scan.sources.get(directive)
        if observed:
            srcs |= observed
        if srcs:
            # 'self' first, then sorted remainder for stable output
            ordered = []
            for keyword in ("'self'", "'none'"):
                if keyword in srcs:
                    ordered.append(keyword)
                    srcs.discard(keyword)
            ordered.extend(sorted(srcs))
            policy[directive] = ordered

    # script-src / style-src: if there are no external sources but the page
    # has inline content, still emit a locked 'self' directive so the inline
    # content is visibly blocked (forcing the dev to refactor or hash).
    if "script-src" not in policy and (scan.has_inline_script or scan.has_inline_handlers):
        policy["script-src"] = ["'self'"]
    if "style-src" not in policy and scan.has_inline_style:
        policy["style-src"] = ["'self'"]

    if allow_inline:
        if scan.has_inline_script or scan.has_inline_handlers:
            policy.setdefault("script-src", ["'self'"])
            if "'unsafe-inline'" not in policy["script-src"]:
                policy["script-src"].append("'unsafe-inline'")
        if scan.has_inline_style:
            policy.setdefault("style-src", ["'self'"])
            if "'unsafe-inline'" not in policy["style-src"]:
                policy["style-src"].append("'unsafe-inline'")

    return policy


def policy_to_header(policy: dict) -> str:
    parts = []
    for directive, sources in policy.items():
        if sources:
            parts.append(f"{directive} {' '.join(sources)}")
        else:
            parts.append(directive)
    return "; ".join(parts)


def parse_policy(header: str) -> dict:
    """Parse a CSP header string into an ordered {directive: [sources]} dict.

    Raises TypeError on non-string input and ValueError on an empty/whitespace
    string.
    """
    if not isinstance(header, str):
        raise TypeError(
            f"parse_policy: header must be a str, got {type(header).__name__}"
        )
    if not header.strip():
        raise ValueError("parse_policy: header must not be empty")
    policy: dict = {}
    for chunk in header.split(";"):
        chunk = chunk.strip()
        if not chunk:
            continue
        tokens = chunk.split()
        directive = tokens[0].lower()
        sources = tokens[1:]
        policy[directive] = sources
    return policy


# --------------------------------------------------------------------------- #
# Policy auditing (csp-evaluator spirit)
# --------------------------------------------------------------------------- #
_DANGEROUS_SCHEMES = {"data:", "http:", "https:", "*", "blob:", "filesystem:"}
_FETCH_DIRECTIVES = {
    "script-src", "style-src", "img-src", "font-src", "connect-src",
    "frame-src", "media-src", "object-src", "child-src", "worker-src",
    "manifest-src",
}


def _is_wildcard(src: str) -> bool:
    s = src.lower()
    if s == "*":
        return True
    # scheme-only wildcard like https: or http:
    if s in ("https:", "http:", "data:", "blob:", "filesystem:"):
        return True
    # host wildcard like *.example.com or https://*
    if "*" in s:
        return True
    return False


def audit_policy(policy: dict) -> list:
    """Return a list[Finding] describing weaknesses in a parsed CSP.

    Raises TypeError on non-dict input and ValueError on an empty dict.
    """
    if not isinstance(policy, dict):
        raise TypeError(
            f"audit_policy: policy must be a dict, got {type(policy).__name__}"
        )
    if not policy:
        raise ValueError("audit_policy: policy dict must not be empty")
    findings: list = []
    F = findings.append

    has_default = "default-src" in policy
    default_src = policy.get("default-src", [])

    # --- missing default-src ------------------------------------------- #
    if not has_default:
        F(Finding("default-src", Severity.HIGH,
                  "No default-src: directives without an explicit rule fall back "
                  "to allowing everything."))

    # --- object-src --------------------------------------------------- #
    object_src = policy.get("object-src")
    if object_src is None and ("'none'" not in default_src):
        F(Finding("object-src", Severity.HIGH,
                  "Missing object-src and default-src is not 'none'; plugins "
                  "(Flash/applet) can be a script-execution vector. Set "
                  "object-src 'none'."))
    elif object_src is not None and object_src != ["'none'"] and any(
            s != "'none'" for s in object_src):
        F(Finding("object-src", Severity.MEDIUM,
                  "object-src is not 'none'; prefer object-src 'none'.",
                  " ".join(object_src)))

    # --- base-uri ----------------------------------------------------- #
    if "base-uri" not in policy:
        F(Finding("base-uri", Severity.MEDIUM,
                  "Missing base-uri; an injected <base> tag can hijack relative "
                  "URLs and bypass script-src. Set base-uri 'self' or 'none'."))

    # --- frame-ancestors (clickjacking) ------------------------------- #
    if "frame-ancestors" not in policy:
        F(Finding("frame-ancestors", Severity.MEDIUM,
                  "Missing frame-ancestors; page may be framed for clickjacking. "
                  "Set frame-ancestors 'self' (or 'none')."))
    else:
        fa = policy["frame-ancestors"]
        if "*" in fa:
            F(Finding("frame-ancestors", Severity.HIGH,
                      "frame-ancestors allows any origin (*); clickjacking is "
                      "possible.", " ".join(fa)))

    # --- form-action -------------------------------------------------- #
    if "form-action" not in policy:
        F(Finding("form-action", Severity.LOW,
                  "Missing form-action; forms may post to attacker origins. "
                  "Consider form-action 'self'."))

    # --- per-directive source checks ---------------------------------- #
    for directive, sources in policy.items():
        if directive not in _FETCH_DIRECTIVES and directive != "default-src":
            continue
        lower = [s.lower() for s in sources]

        if "'unsafe-inline'" in lower:
            sev = Severity.HIGH if directive in ("script-src", "default-src") else Severity.MEDIUM
            has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                                    for s in lower)
            if has_nonce_or_hash:
                F(Finding(directive, Severity.LOW,
                          "'unsafe-inline' present alongside a nonce/hash; modern "
                          "browsers ignore 'unsafe-inline' when a nonce/hash is "
                          "set, but remove it to be safe.", "'unsafe-inline'"))
            else:
                F(Finding(directive, sev,
                          "'unsafe-inline' allows inline scripts/styles — a primary "
                          "XSS vector. Use nonces or hashes instead.",
                          "'unsafe-inline'"))

        if "'unsafe-eval'" in lower:
            F(Finding(directive, Severity.HIGH,
                      "'unsafe-eval' allows eval()/new Function() — enables many "
                      "XSS payloads. Remove it.", "'unsafe-eval'"))

        if directive in ("script-src", "default-src") and "data:" in lower:
            F(Finding(directive, Severity.HIGH,
                      "data: in script-src allows attacker-controlled inline "
                      "scripts via data: URIs. Remove it.", "data:"))

        for s in sources:
            if _is_wildcard(s):
                sev = Severity.HIGH if directive in ("script-src", "default-src") else Severity.MEDIUM
                F(Finding(directive, sev,
                          f"Wildcard / scheme source '{s}' is overly broad and "
                          f"may allow untrusted content.", s))

    if not findings:
        F(Finding("policy", Severity.INFO, "No weaknesses detected by CSPBUILDER's heuristics."))

    findings.sort(key=lambda f: Severity.ORDER.get(f.severity, 99))
    return findings
