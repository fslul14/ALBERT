# checks/security_txt.py: security.txt (RFC 9116) + /.well-known/ hygiene

Fetched once per run, only at `/.well-known/security.txt` (the legacy `/security.txt` is never
guessed): by `quick` (final page's origin) and by `scan` (the crawler, right after robots.txt;
robots.txt disallow is respected). The crawler marks it seen, so it is never re-fetched or
re-checked as a page, and the family runs once on that fetch chain: findings aren't duplicated.

Field validation (since step 6): missing / HTML soft-404, not `text/plain`, no Contact, plain-
http Contact, Expires missing/invalid/expired/>1 year (Low/Info).
RFC 9116 location/format (step 20): every hop of the fetch (incl. redirects) on HTTPS (s.3,
Low); Expires / Preferred-Languages at most once (s.2.5.5/2.5.8, Low); Canonical lists the
fetched URL (s.2.5.2, Info). Redirects follow the normal scope rules.

/.well-known/ hygiene is limited to the security.txt location itself: other well-known files
(e.g. change-password) are not probed, since fetching them would mean guessing they exist.
