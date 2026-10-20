# External intelligence: core/intel.py + core/intel_sources.py + checks/intel_lookups.py

Only with `albert scan <url> --full`; off in a plain scan and in `quick`. Third-party services
only, **never the target**: no request is ever sent to the target host. The target's domain
is sent only as each service's query subject.

| Source | Endpoint (exact, allow-listed in `INTEL_ENDPOINTS`) | Domain sent as |
|---|---|---|
| Certificate Transparency | `GET https://crt.sh/` | `q=%.<domain>` |
| Wayback Machine | `GET https://web.archive.org/cdx/search/cdx` | `url=<domain>/*` |
| Google Safe Browsing v4 | `POST https://safebrowsing.googleapis.com/v4/threatMatches:find` | `threatEntries` (https/http root URLs) |
| DNS blocklists (`IntelDnsPolicy`) | A lookups under `dbl.spamhaus.org`, `multi.surbl.org` (domain), `zen.spamhaus.org` (in-domain MX IPv4, globally routable only) | the DNS name |

Safe Browsing needs `ALBERT_SAFE_BROWSING_KEY`; without it the source is skipped with a note.
The key is never written to messages or reports. Blocklist answers `127.255.255.x` mean the
query was refused (Spamhaus refuses many public resolvers): reported as not assessed, never
as a listing, and not cached. Results are cached under `reports/.cache/intel/` for a day.
Any failure degrades to "INTEL-NOT-ASSESSED" (Info); the scan never fails.

**Discovered hosts are never contacted.** CT subdomains are reported with their scope status
("in scope" only when scope.toml has an entry). Nothing feeds them to the crawler or any client;
scanning one needs its own scope entry. Wayback URLs are reported, never fetched.

Severity: CT subdomains and Wayback URLs Info; domain on DBL/SURBL or MX IP on ZEN (SBL/XBL)
Medium; MX on ZEN PBL (policy list) Low; Safe Browsing match High.

## Open item (TODO)

- **crt.sh success-path shape is unverified live.** During the step-19 live check (2026-10-20)
  crt.sh returned `502 Bad Gateway` on every attempt (example.com and badssl.com, full and
  `exclude=expired` queries), so only its error path was exercised. The parser
  (`intel_sources._crt_sh`) is tested against fixtures modelled on the documented JSON format;
  **wildcard (`*.`) / duplicate / uppercase name handling in `name_value` still needs one live
  confirmation** once crt.sh recovers: a single `--full` lookup, or one request through
  `IntelClient`, comparing the raw rows with the parsed subdomain list.
- Verified live on the same date: Wayback CDX shape (and the `filter=statuscode:200` fix).
