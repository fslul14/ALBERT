# checks/fingerprint.py: technology fingerprinting (scan only)

Signatures are data: `albert/data/fingerprints.yaml` (format at the top of the file;
validated by `albert rules lint`). Add a technology by adding an entry. Each may carry `cpe`
(vendor:product) and/or `npm` identifiers for vulnerability lookup in step 16.

**Signals (already collected, nothing extra probed):** headers of every collected response,
Set-Cookie names, `<meta>` and markup of crawled pages and rendered DOMs, `<script src>` URLs
and rendered script requests, script bodies (step-14 scripts), crawled page URLs, and the MD5
of favicons that crawled pages reference with `<link rel=icon>` on the same host (at most 2;
`/favicon.ico` is never guessed).

**Confidence:** a version from headers, meta, markup or a script's own banner is **High**;
a version read from a URL path (e.g. `jquery-3.5.1.min.js`) is **Low**; presence-only is High
for headers/meta, Medium otherwise; technologies only implied by another are Low. One
detection per (technology, version); presence signals fold into the best versioned one, so two
loaded jQuery versions stay two detections.

**Output:** `ScanResult.tech` -> the report appendix "Technology detected" table (and JSON
`appendix.tech`). Not findings: judging versions (CVEs) is step 16.

No favicon hashes ship yet: only verified hashes belong in the file.
