# CVE matching: core/intel.py + core/vulndb.py + checks/cve.py (scan only)

`albert scan <url> --cve {off,cache,online}` (default **cache**).

- **cache** (default): matches only against data already in `reports/.cache/vulndb/` (fully
  local, no network). No cached data -> an Info note "Versions detected, CVE lookup unavailable".
- **online**: queries third-party vulnerability databases, **never the target**:
  - OSV.dev `POST https://api.osv.dev/v1/query` for npm packages (`npm` id in signatures);
  - NVD `GET https://services.nvd.nist.gov/rest/json/cves/2.0` for CPE products (`cpe` id).
  Only package/product names and versions are sent. Results are cached (fresh 7 days; a
  stale cache is used if the DB is unreachable). Failures never fail the scan.
- **off**: no matching.

`core/intel.py` is the checkpoint for this egress path (separate from the target-facing
`HttpClient`, which is GET/HEAD-only): exactly the two endpoints above, their methods, HTTPS,
never a scan-target host; enforced in the transport before sending (AST-tested), with polite
per-service spacing (NVD: 6.5 s without an API key) and a request budget.

**Eligibility:** only versioned detections with an npm/cpe id; presence-only never matched.

**Confidence = min(detection confidence, match certainty).** Certainty: OSV package match
High; NVD CPE version range Medium (distros backport fixes without changing versions); NVD
match that also needs a specific platform Low. So a version read from a URL path (Low) can't
produce a High-confidence CVE finding, however severe. **Severity** from CVSS: the NVD score,
or a CVSS 3.x base score computed from OSV's vector, else the advisory's label.

NVD product CVE lists are cached whole and version ranges are evaluated locally (pure,
offline-testable); OSV filters by version server-side.
