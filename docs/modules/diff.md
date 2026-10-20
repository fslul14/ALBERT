# core/diff.py: scan diffing

`albert scan <url> --diff <prior.json>` compares this scan with a prior JSON report and adds a
"Changes since last scan" section (after the executive summary) and a `diff` object in the JSON.

The prior file is validated **before the scan starts**; it is refused (exit 2, nothing sent)
if it's unreadable, not an Albert report, for a different host, a different mode (quick vs
scan), or a different `schema_version` (`models.REPORT_SCHEMA_VERSION`).

Matching: by finding id; where one id covers several findings in a report (e.g. `HDR-CDN-WAF`
per provider) the title disambiguates. Findings and Info posture notes are both compared.

| Category | Meaning |
|---|---|
| new | only in the current report |
| resolved | only in the prior report, and its check family ran this time |
| changed | same finding, but severity, confidence, title or affected-URL set differs (details listed) |
| unchanged | identical in those respects |
| not re-checked | only in the prior report, but its family didn't run this time (e.g. prior used `--full`), so "resolved" would be wrong |
