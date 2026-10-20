# Rules engine (core/engine.py + albert/rules/*.yaml)

A rule file is `albert/rules/<family>.yaml`: `{rules: [...]}`; top-level `x-*` keys hold YAML
anchors (e.g. the sensitive-cookie-name regex). The file name is the family the rules join
(`headers`, `cookies`); `run_family()` merges a family's Python checks with its rules and
groups findings across pages. The format is documented at the top of `core/engine.py`.

Adding a pattern check = adding a rule, then `albert rules lint` (unique ids, required fields,
valid severity/confidence, compilable regexes, known keys/placeholders, cookie ids that carry
`{cookie_id}`). `albert rules list` prints them. Report headers show
`<n> rules, sha256:<hash>`.

In YAML: header presence/absence (nosniff, Permissions-Policy, COOP/COEP/CORP), version and
technology banners, deprecated headers, debug/backend headers, cookie Secure/HttpOnly/SameSite.
In Python (needs logic): CSP, framing, HSTS, Referrer-Policy, cache, Server-Timing, private
IPs, trace IDs, ETag, CDN/WAF, protocols, cookie Domain/Path/prefix, CORS, TLS, rendered DOM,
disclosure, security.txt.

Migration proof: `tests/test_rules_migration.py` compares the rule-backed output against a
golden snapshot produced by the pre-migration Python checks (commit 20a6884).
