# core/crawler.py

Async same-host crawler. Every request goes through `HttpClient`, so `scope.py` runs first.

- **Scope:** links are followed only on the start URL's exact host; other hosts (subdomains
  included) are listed as `off-host` and never contacted.
- **robots.txt:** disallowed paths are never fetched; `Crawl-delay` lowers the rate. RFC 9309:
  4xx means allow-all, 5xx/unreachable means nothing is crawled.
- **Seeds:** sitemaps listed in robots.txt, else `/sitemap.xml` (nested indexes, max 5 files).
  `<loc>` values are extracted with a regex, not an XML parser (no entity-expansion risk).
- **Dedup:** fragments dropped, query params sorted, default ports and host case normalized,
  trailing slash ignored for dedup (the URL is fetched as linked).
- **Caps / traps:** depth, page count and request budget; session-id URLs, repeating path
  segments, >2000-char URLs, and URL shapes seen too often (calendar-like: 5, else 20) are
  skipped and reported once.
- **Blocks:** 429/503/WAF-challenge responses are recorded, the crawl pauses (Retry-After
  honored, capped), and stops after `max_blocks`.

## Resume state: `reports/.state/<host>.jsonl` (gitignored)

Written so an interrupted scan can resume without re-fetching completed pages. Deleted after a
clean finish (including the page cap); kept after a crash, interruption, or block/budget stop.

One JSON object per line:

| Record | Fields retained |
|---|---|
| meta (first line) | `start_url`, format version `v` |
| `page` (each fetched hop) | URL (secrets redacted), status, HTTP version, depth, first-hop flag, **sanitized headers** |
| `link` (each queued URL) | URL, depth |

What is **not** retained (CWE-312):

- **No response bodies.** Remaining work comes from the `link` records, not from re-parsing HTML.
- **No `Authorization`, `Proxy-Authorization`, or `Cookie` headers.**
- **No cookie values:** `Set-Cookie` is stored as `name=` plus its attributes (Path, Secure,
  HttpOnly, SameSite, ...) so cookie checks still work on resumed pages.
- **Every other header value** is swept with `secrets.redact()`.
- **Links whose URL contains a secret-looking token** are not written at all (they're counted in
  a report note). They are lost on resume unless found again.

Trade-off: resumed pages carry headers only, so body-based checks (added in later steps) don't
re-run on them; the report notes how many responses were resumed.
- `--exclude REGEX` (scan): enforced at the HTTP client gate, so matching URLs are never requested
  by any path (links, sitemap seeds, redirects, scripts, render sub-requests, the TLS-step
  redirect check). Links are recorded as skipped (`matches --exclude`); a redirect into one
  is recorded as not followed.
