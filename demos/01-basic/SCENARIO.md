# Demo 01 — Build a least-privilege CSP, then audit a weak one

CSPBUILDER is a **defensive / authorized-testing** tool. It only analyzes HTML you
own (or are authorized to test) and reasons about CSP strings. It performs no
network requests and has no attack capability.

## Scenario

`sample_page.html` is a realistic single-page dashboard for `https://app.acme.com`.
It loads resources from several origins:

- **styles** — first-party `/css/app.css` + Google Fonts CDN
- **scripts** — jsDelivr (chart.js) + first-party `/js/app.js`
- **images** — first-party logo/favicon + two CDNs
- **frame** — a `widgets.acme.com` status widget
- **fonts** — an `@font-face` woff2 on `cdn.acme.com`
- **connect** — `fetch()` to `api.acme.com`, a `WebSocket` to `stream.acme.com`,
  plus a `preconnect` hint
- **inline** — an inline `<script>`, inline `<style>`, an `onclick=` handler, and a
  `setTimeout("...")` string (an eval-style hint)

## 1. Generate a CSP from what the page actually loads

```sh
python -m cspbuilder build demos/01-basic/sample_page.html \
    --url https://app.acme.com
```

Same-origin resources collapse to `'self'`; every external origin becomes an
explicit allow-list entry. The baseline is hardened automatically
(`default-src 'self'`, `object-src 'none'`, `base-uri 'self'`,
`frame-ancestors 'self'`, `form-action 'self'`). Inline content is **not**
allowed — the tool warns that the `onclick=` handler and inline `<script>` will
be blocked until refactored to nonces/hashes. Because warnings are present, the
command exits non-zero.

JSON for tooling/CI:

```sh
python -m cspbuilder --format json build demos/01-basic/sample_page.html --url https://app.acme.com
```

## 2. Audit an existing, weak policy

```sh
python -m cspbuilder audit \
    --policy "default-src *; script-src 'unsafe-inline' 'unsafe-eval' https:"
```

This reports HIGH findings for `'unsafe-inline'`, `'unsafe-eval'`, the `*`
wildcard, the `https:` scheme source, and the missing `object-src`/`base-uri`.
Exit code is `1` because HIGH/MEDIUM findings exist.

A clean policy returns an INFO finding and exit code `0`:

```sh
python -m cspbuilder audit --policy "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"
```

## Exit codes

- `0` — build produced a fully locked-down policy, or audit found nothing actionable
- `1` — build emitted warnings (inline/eval), or audit found HIGH/MEDIUM weaknesses
- `2` — usage / file IO error

## Scope

Static analysis of HTML you control and of CSP strings. No live capture, no
network connections, no attack traffic — appropriate for authorized testing and
defensive review only.
