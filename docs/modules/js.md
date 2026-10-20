# checks/js.py: JavaScript analysis (scan only)

**Input (nothing new is probed):**
- Same-host `<script src>` files referenced by crawled pages, fetched by the crawler after
  the page crawl (scope- and robots-checked, `CrawlLimits.max_scripts`, default 50). This is
  the passive rule's "scripts found on in-scope pages"; third-party scripts are never fetched.
- Scripts the renderer fetched (`--render`), kept from its in-scope requests.
- Inline `<script>` blocks (incl. JSON data blobs) in crawled HTML.

`.map` files are **never requested**: references (`sourceMappingURL`, `SourceMap`/`X-SourceMap`
headers) are reported, resolved but not fetched.

**Checks:**
- Secrets (`core/secrets.py` patterns), severity by type from `secrets.PATTERN_SEVERITY` (same
  table as the DOM-secret check): AWS/Stripe/GitHub/private keys High, JWT Medium, Google API
  key Low, generic `key = "..."` Low/low-confidence (placeholders like `YOUR_API_KEY` skipped).
- Source maps: referenced (Info), embedded `data:` map (Low), a `.map` received as a normal
  response (Low).
- Internal hosts / localhost / private-IP URLs (Low); staging/test hostnames, judged on
  subdomain labels only so `dev.to` or `developer.mozilla.org` don't count (Low).
- Framework dev builds: React/Vue/Angular/webpack-dev-server markers (Low); debug-flag
  assignments like `debug:!0` (Info, low confidence).

**Redaction:** each script is redacted in full (`secrets.redact_with_matches`) before any
snippet is cut, so evidence can never contain a partial token. Markers keep at most a short
identifying prefix (e.g. `sk_live_...`), per the step-1 redaction design.
