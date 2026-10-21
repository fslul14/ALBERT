# TLS / certificate module

- `core/certs.py`: pure X.509 parsing (`cryptography`) into `CertInfo`.
- `core/tls_client.py`: the collector. It opens its own sockets, so **every function that
  touches the network calls `policy.check_host()` as its first statement** (enforced by an
  AST test), the same checkpoint `HttpClient` uses. Off-scope hosts raise before DNS/sockets.
  - stdlib `ssl`: a verified handshake (system trust store) captures OpenSSL's verify
    error; an unverified handshake reads the leaf cert, protocol and cipher.
  - sslyze 6.3.1 (pinned), **non-intrusive commands only** (`SSLYZE_COMMANDS`):
    `CERTIFICATE_INFO` and the six per-protocol cipher-suite enumerations (SSLv2 to TLS 1.3).
    Never Heartbleed, CCS injection, renegotiation, ROBOT, compression, fallback SCSV, early
    data, session resumption, EMS, elliptic curves, or sslyze's own HTTP request. A test
    asserts the source mentions no other `ScanCommand`. Enumeration means many handshakes
    (2 concurrent per server).
- `checks/tls.py`: pure checks. A failed verification maps to **exactly one** validity
  finding (expired / not yet valid / hostname mismatch / self-signed: High; untrusted: High;
  incomplete chain: Medium). Also: expiring < 14 days, SHA-1/MD5 signatures, weak keys,
  SSLv2/3 (Medium), TLS 1.0/1.1 (Low), no TLS 1.2+, insecure / non-forward-secret ciphers,
  embedded SCTs (Info), HTTP->HTTPS redirect and HTTPS->HTTP downgrade.
- HTTP->HTTPS redirect: uses the page's own hops when the start URL was `http://`; otherwise
  `quick`/`scan` GET `http://<host>/` once (the start URL over plain HTTP).
- `albert quick <url> --tls-only`: handshakes and cert inspection only, no HTTP requests.
- `albert scan <url> --no-tls-enum`: certificate handshake + inspection only (validity, expiry,
  hostname, chain); sslyze enumeration is skipped. For vendor-hosted hosts (Shopify, Vercel)
  whose protocol/cipher config is the platform's, not the site owner's.
