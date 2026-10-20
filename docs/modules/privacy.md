# checks/privacy.py: privacy / tracking observations (scan)

Pure over data already collected. **Albert never contacts a tracker:** the step-11 browser
refusal is unchanged (third-party requests are aborted and recorded, never fetched). This
module reads those recorded attempts, plus, without `--render`, `<script>`/`<img>`/`<iframe>`/
stylesheet references in crawled HTML (lower confidence; `type="text/plain"` consent-gated
scripts are skipped because a browser wouldn't load them).

Signatures: `albert/data/trackers.yaml` (46 services: analytics, advertising, session replay,
fingerprinting, tag managers, monitoring, consent managers), validated by `albert rules lint`.

| Finding | Severity |
|---|---|
| Third-party origins pages loaded (count + per-origin requests/pages) | Info |
| Known trackers among them (monitoring/consent not counted) | Info |
| Tracking before consent: tracker loads attempted on first visit, or first-party tracking cookies set by the server | Low |
| Trackers present but no consent manager / banner markup detected | Low (low confidence) |
| Browser fingerprinting: vendor signature (medium conf) or canvas+WebGL+audio probing (low conf) | Low |
| Consent manager detected | Info |
| No privacy policy link on any page | Info |

**Limit:** third-party `Set-Cookie` is never observable (third-party responses are never
fetched). "Before consent" holds because Albert never interacts with a page; a banner injected
by a refused third-party script can be missed, so the CMP's own loader request also counts.
