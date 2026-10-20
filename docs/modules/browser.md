# core/browser.py + checks/rendered.py

Opt-in via `albert scan <url> --render [--render-max N]` (default 10 pages). One-time setup:
`.venv\Scripts\playwright install chromium`.

## The browser has no network of its own

- Chromium launches with `--host-resolver-rules=MAP * ~NOTFOUND` and a dead proxy
  (`127.0.0.1:9`, loopback included), so anything that escaped interception (preconnect,
  WebRTC, background services) fails. OS sandbox on (`chromium_sandbox=True`).
- Every request is intercepted (`page.route`). `policy.check_request` runs **first**:
  off-scope hosts (third-party CDNs, analytics) and non-GET/HEAD methods are aborted and
  recorded, never fetched. In-scope requests are fetched by `HttpClient` (scope, per-host
  rate limit, budget, honest UA) and replayed into the page. Set-Cookie is stripped, so the
  page never holds or sends cookies.
- Service workers blocked; WebSockets closed and recorded; window.open popups closed;
  downloads off.
- No script injection and no interaction: no `evaluate`/init scripts/locator actions/form
  fills/clicks (AST-tested). The DOM is read with DevTools `DOM.getOuterHTML`.

Consequence: third-party scripts don't execute (their requests are refused), so the DOM is
what the site's *own* code produces. Out-of-scope origins are listed in the report under
"Skipped / not followed" with request counts.

## Checks (pure over `RenderedPage`)

Mixed content (active Medium, passive Low; from requests *and* DOM, since browsers block
active mixed content before requesting it); password field on an HTTP page (High); form on
an HTTPS page submitting over HTTP (Medium, High with a password field); cross-origin form
post (Low, Medium with password); third-party script without SRI (Low), SRI without
crossorigin (Low), third-party stylesheet without SRI (Info); `target=_blank` without
noopener (Info); known secret formats in the DOM (redacted; severity by type).

`<meta>` CSP: the header check reads `<meta http-equiv=Content-Security-Policy>` from static
HTML and reports `HDR-CSP-META-ONLY` (Low) plus quality issues instead of
`HDR-CSP-MISSING`; after rendering, `reconcile_meta_csp` does the same for meta CSPs
inserted by JavaScript.
