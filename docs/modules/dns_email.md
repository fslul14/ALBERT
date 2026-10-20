# DNS and email security: core/dns_client.py + checks/dns_email.py

Runs in `albert quick` (always) and in `albert scan` with `--full`.

**Scope (DnsPolicy, checked before every query; AST-tested):** only names equal to or under the
target's registrable domain, and only A/AAAA/CNAME/MX/TXT/CAA/DS/DNSKEY/TLSA/NS; budget of 60
queries. Never queried: third-party SPF includes (`include:_spf.google.com` counts as one
lookup, so the 10-lookup check reports "at least N"), MX hosts at other domains (DANE is
checked only for in-domain MX), and DKIM selectors (never guessed: DKIM is "not assessed").
Queries go to the system's recursive resolver.

**MTA-STS policy:** if `_mta-sts` TXT exists, exactly one HTTPS file is fetched,
`https://mta-sts.<domain>/.well-known/mta-sts.txt`, via `ScopePolicy.for_mta_sts` (that path
only, https only, no query string) and without following redirects (RFC 8461).

**Checks (pure over DnsSnapshot):**
- Medium: no DMARC, invalid/duplicate DMARC, DMARC p=none, SPF +all.
- High: CNAME to a takeover-prone service (Heroku, S3, GitHub Pages, Azure, ...) whose target
  is NXDOMAIN (medium confidence). CNAME to anything else that doesn't resolve: Low.
- Low: no/duplicate/invalid SPF, ?all or no all, >10 lookups, DMARC pct<100 or sp=none, no CAA
  (closest record walking up to the registrable domain), no DNSSEC (no DS), no MTA-STS
  (mail domains), MTA-STS policy unusable or not covering every MX.
- Info: SPF ptr, no DMARC rua, MTA-STS testing/none, no TLS-RPT, no BIMI (only when DMARC is
  enforcing), no DANE/TLSA for in-domain MX, DKIM not assessed.
- Null MX (`0 .`) skips the mail-transport checks.

A record whose lookup failed (or wasn't queried) is never reported as missing: its checks are
skipped and listed under "Some DNS records could not be looked up" (Info).

**Tests** inject a fake resolver. `tests/conftest.py` replaces dnspython's send functions and
fails any test that attempts a real DNS query (dnspython swallows the error, so the fixture
fails the test afterwards).
