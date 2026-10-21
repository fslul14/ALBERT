# Albert: a passive web security scanner

Albert audits a website using **only what the site serves to a normal visitor**. It crawls,
renders JavaScript, inspects TLS, DNS and email posture, fingerprints the technology stack,
matches versions to known CVEs, checks privacy and tracking, and writes a Markdown + JSON
report. **It detects; it never exploits.**

## The boundary (read this first)

- **Passive only.** Albert sends `GET`/`HEAD` requests for the start URL, links and scripts
  found on in-scope pages, and standard well-known files (`/robots.txt`, `/sitemap.xml`,
  `/.well-known/security.txt`). It never sends payloads, fuzzes, submits forms, logs in, guesses
  paths or subdomains, port-scans, or sends crafted headers or `Origin` values to probe behavior.
- **Authorization is required for scans.** `albert scan` refuses any host without an entry in
  `scope.toml` that names who authorized it (your own site, a friend's site with written OK, or
  a bug-bounty/VDP program within its published scope). `albert quick` checks a single page,
  the same surface Mozilla Observatory or SSL Labs check on request.
- **One checkpoint for all traffic.** Every network path (HTTP client, TLS sockets, DNS, the
  headless browser, third-party intel lookups) passes a scope check before any socket opens.
  Static tests fail the build if code reaches the network another way.
- **The headless browser has no network of its own.** It runs the site's own scripts, but every
  request it makes is scope-checked and fetched through Albert's client. Third-party loads
  (CDNs, trackers) are recorded and refused, never fetched; nothing is clicked, filled or
  injected.
- **Third-party intelligence never touches the target.** `--full` queries crt.sh, the Wayback
  Machine, DNS blocklists and (with a key) Google Safe Browsing *about* the domain. Hosts they
  reveal are reported, never contacted.
- **Polite and honest.** Per-host rate limit, concurrency cap, request budget, timeouts,
  robots.txt respected, blocks and rate limits respected (Albert backs off rather than
  evading), and an honest User-Agent: `Albert/<version> (passive security scanner; ...)`.
- **Secrets never reach a report.** Evidence is redacted when it's created, and the whole
  report is swept again before it's written.

There is **no active or exploitation mode**. A separate, triple-gated `active` module
(exposed-file probing, bounded discovery, open-redirect detection) is planned as Phase 3
but **not built**.

## Install (Windows)

Requires Python 3.11+.

```powershell
git clone https://github.com/fslul14/ALBERT.git
cd ALBERT
py -3 -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\playwright install chromium   # only needed for --render
```

On macOS/Linux, use `.venv/bin/` instead of `.venv\Scripts\`.

## Usage

```text
albert quick <url>                      # one page, any public URL, no scope entry needed
albert quick <url> --no-tls-enum        # same, certificate handshake only (vendor-hosted hosts)
albert scan  <url> [options]            # authorized full crawl (needs a scope.toml entry)
albert rules lint | list                # validate / list YAML rules and signature files
```

| | `quick` | `scan` | `scan --full` |
|---|---|---|---|
| Needs `scope.toml` entry | no | yes | yes |
| Pages | the start page (+ same-site redirect) | crawl (robots, sitemap, caps) | crawl |
| Headers, cookies, CORS, disclosure, security.txt, TLS | yes | yes | yes |
| DNS / email (SPF, DMARC, MTA-STS, DNSSEC, ...) | yes | | yes |
| JS analysis, fingerprinting, CVE matching, privacy | | yes | yes |
| Headless render (`--render`) | | optional | optional |
| External intel (CT logs, Wayback, blocklists, Safe Browsing) | | | yes |

Scan options: `--render [--render-max N]`, `--max-pages N`, `--max-depth N`,
`--max-scripts N` (0 disables script fetching), `--rate R` (requests/second per host),
`--resume`, `--cve {cache,online,off}` (default `cache`: fully local; `online` queries
OSV.dev/NVD about package versions), `--no-tls-enum` (TLS: certificate handshake only, no
sslyze protocol/cipher enumeration; for vendor-hosted targets), `--exclude REGEX` (URLs
matching it, e.g. login/account paths, are recorded as skipped and never requested),
`--diff prior.json`, `--out DIR`, `--format md,json`.

`scope.toml` (gitignored) looks like `scope.example.toml`:

```toml
[[target]]
host = "example.com"
authorized_by = "self (own domain)"
date = "2026-10-20"
allow_active = false
```

If a scanned host has no entry, Albert asks who authorized it and records the answer.

### Example

```text
> .venv\Scripts\albert.exe quick https://badssl.com/ --tls-only
badssl.com: 1 medium, 2 low, 1 info (0 pages)
  reports\badssl.com_2026-10-20_1413.md
  reports\badssl.com_2026-10-20_1413.json
```

A report has a header (target, mode, scope entry, timing, tool and rules version), an executive
summary (counts by severity, posture grade, top issues), full findings for Low and above (each
with ID, severity, confidence, URLs, redacted evidence, impact, remediation and CWE/OWASP/CVE
references), a compact table of Info "posture notes", an optional "Changes since last scan"
section, and an appendix (pages, skipped/blocked URLs, detected technologies, errors). The
JSON mirrors the Markdown.

**Posture grade:** each severity has a weight (Critical 40, High 25, Medium 10, Low 3).
Repeats within a severity cost half the previous one, and each penalty is scaled by
confidence. Any Critical caps the grade at D, and any High at C. A: 92+, B: 80+, C: 65+, D: 50+.

## What it does and doesn't do

**Does:**
- **Headers and cookies:** CSP quality, HSTS, framing, CORS as served, cookie flags and
  prefixes.
- **TLS:** certificate validity, deprecated protocols and weak ciphers (sslyze, non-intrusive
  scans only).
- **Disclosure:** debug pages, stack traces, DB errors, directory listings, credential-looking
  comments (masked).
- **JavaScript:** secrets (redacted), source-map references, internal and staging hosts,
  development builds.
- **Fingerprinting:** technologies from signatures, then CVE matching with honest confidence.
- **DNS and email:** SPF, DMARC, MTA-STS, TLS-RPT, BIMI, DANE, CAA, DNSSEC, dangling CNAMEs.
- **Privacy:** third-party origins, trackers, tracking before consent, consent banners,
  fingerprinting scripts.
- **External intelligence:** Certificate Transparency subdomains, historical URLs, blocklists.
- **Standards:** security.txt (RFC 9116).
- **Workflow:** scan diffs, resumable crawls.

**Doesn't:**
- exploit, inject, brute-force or bypass anything;
- authenticate, or scan behind a login;
- fetch third-party resources, or contact hosts it discovers;
- guess paths, subdomains or DKIM selectors;
- evade WAFs or rate limits.

Severity is deliberately conservative: most passive findings are Low or Medium, and a missing
header is never Critical.

**Known limits:**
- Third-party cookies can't be observed, because third-party responses are never fetched.
- HTTP/2 is inferred from `Alt-Svc`, since the client speaks HTTP/1.1.
- crt.sh's live success-response format is still unverified (see `docs/modules/intel.md`).

## Development

```powershell
.venv\Scripts\python.exe -m pytest -q    # hermetic: no live hosts, DNS or APIs (enforced)
.venv\Scripts\ruff.exe check .
.venv\Scripts\mypy.exe albert tests
```

Module notes are in `docs/modules/`. Checks are pure functions over collected data, and
pattern-style checks are YAML rules (`albert/rules/`). Technology and tracker signatures are
data files (`albert/data/`).
