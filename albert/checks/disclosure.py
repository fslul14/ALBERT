"""Information-disclosure checks over bodies Albert already collected. Pure; never fetches.

False-positive guards:
- Framework debug pages and directory listings match real HTML markup; a tutorial quoting
  one shows it HTML-escaped, so it doesn't match.
- Stack traces, DB errors and server paths: on error responses (>= 400) the whole text is
  searched; on normal pages, text inside <pre>/<code>/<samp>/<kbd>/<textarea>/<blockquote>
  (where tutorials quote examples) is ignored, and confidence drops to Medium.
- Credential-looking comment values are masked here (a bare password has no shape the
  secrets.py backstop would catch).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from urllib.parse import urlsplit

from selectolax.lexbor import LexborHTMLParser

from albert.core.models import (
    CollectedResponse,
    Confidence,
    Evidence,
    Finding,
    Severity,
    group_findings,
)

S, C = Severity, Confidence
A05 = "OWASP A05:2021"
MAX_ITEMS = 20  # per finding, per page

_HTML = {"text/html", "application/xhtml+xml"}
_BODY_TYPES = _HTML | {"text/plain", "application/json", "application/xml", "text/xml"}
_CODE_TAGS = ("pre", "code", "samp", "kbd", "textarea", "xmp", "blockquote")
_NON_TEXT_TAGS = ("script", "style", "noscript", "template")

# (framework, marker on raw HTML)
_DEBUG_PAGES: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.I))
    for name, rx in (
        ("Django", r"seeing this error because you have <code>DEBUG = True</code>"),
        (
            "Werkzeug/Flask",
            r"Werkzeug Debugger</title>|The debugger caught an exception in your WSGI",
        ),
        ("Whoops (PHP)", r"<title>Whoops! There was an error\.</title>"),
        ("Laravel Ignition", r"window\.ignite\s*=|<title>[^<]*\| Ignition</title>"),
        ("Symfony", r'class="exception-message-wrapper"|<div[^>]+class="sf-toolbar'),
        ("Ruby on Rails", r"<title>Action Controller: Exception caught</title>"),
        ("ASP.NET", r"<h1>Server Error in '[^']*' Application\.<hr"),
        ("Spring Boot", r"<h1>Whitelabel Error Page</h1>"),
        ("Apache Tomcat", r"<h3>Apache Tomcat/[\d.]+</h3>"),
    )
)

# (language, frame pattern on text, minimum matches)
_TRACES: tuple[tuple[str, re.Pattern[str], int], ...] = (
    (
        "Python",
        re.compile(r'Traceback \(most recent call last\):\s*\n\s*File "[^"\n]+", line \d+'),
        1,
    ),
    ("Java", re.compile(r"^\s*at [\w$.<>]+\([\w$]+\.java:\d+\)", re.M), 3),
    (
        ".NET",
        re.compile(r"^\s*at (?:System|Microsoft)\.[\w.`<>]+\(|^\s*at .+ in .+:line \d+\s*$", re.M),
        2,
    ),
    ("PHP", re.compile(r"^#\d+ (?:/|[A-Za-z]:\\)[^\n(]+\(\d+\): ", re.M), 2),
    (
        "Node.js",
        re.compile(
            r"^\s*at (?:[\w.<>$\[\] ]+ )?\(?(?:/|[A-Za-z]:\\|node:)[^\n)]+:\d+:\d+\)?\s*$", re.M
        ),
        3,
    ),
    ("Ruby", re.compile(r"^\S+\.rb:\d+:in `", re.M), 2),
    ("Go", re.compile(r"^goroutine \d+ \[running\]:", re.M), 1),
)

_DB_ERRORS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.I))
    for name, rx in (
        (
            "MySQL",
            r"You have an error in your SQL syntax; check the manual that corresponds to "
            r"your (?:MySQL|MariaDB)",
        ),
        ("MySQL", r"\bmysqli?_(?:query|fetch_\w+|num_rows|connect)\(\)|mysqli_sql_exception"),
        (
            "PostgreSQL",
            r"\bPG::\w+Error\b|ERROR:\s{1,2}syntax error at or near|pg_query\(\): Query failed",
        ),
        (
            "Microsoft SQL Server",
            r"Unclosed quotation mark after the character string"
            r"|\[Microsoft\]\[ODBC SQL Server Driver\]|System\.Data\.SqlClient\.SqlException",
        ),
        ("Oracle", r"\bORA-\d{5}: "),
        ("SQLite", r"SQLite3::SQLException|sqlite3\.OperationalError|SQLITE_ERROR"),
        ("PDO", r"SQLSTATE\[[0-9A-Z]{5}\]"),
        ("JDBC/Hibernate", r"java\.sql\.SQL\w*Exception|org\.hibernate\.\w+Exception"),
    )
)

_SERVER_PATH = re.compile(
    r"(?<![\w/.:%-])(?:/(?:var/www|home/[\w.-]+|usr/local|usr/share/nginx|srv|opt|var/lib"
    r"|Users/[\w.-]+)/[\w./-]+\.(?:php|py|rb|js|ts|java|jsp|aspx?|cs|go|pl|inc|conf|ya?ml|json"
    r"|env|ini)|[A-Z]:\\(?:inetpub|xampp|wamp\w*|Users|Program Files(?: \(x86\))?|www|sites"
    r"|websites|apps?)\\[^\s<>\"'|]+)",
)

_LISTINGS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(rx, re.I))
    for name, rx in (
        ("Apache/nginx autoindex", r"<title>Index of /[^<]*</title>[\s\S]{0,800}?<h1>Index of /"),
        ("IIS", r"\[To Parent Directory\]</A>"),
        ("Python http.server", r"<title>Directory listing for /[^<]*</title>"),
        ("Tomcat", r"<title>Directory Listing For /"),
        ("lighttpd", r'<table summary="Directory Listing"'),
    )
)

_CRED = re.compile(
    r"(?i)\b(pass(?:word|wd|phrase)?|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|"
    r"token|credentials?|db[_-]?pass(?:word)?)\b\s*(?:[:=]|\bis\b)\s*['\"]?([^\s'\",;<>]{3,})"
)
_URL_CRED = re.compile(r"\b([a-z][a-z0-9+.-]*://[^\s/:@]+:)([^\s/@]+)(@)", re.I)
_PLACEHOLDER = re.compile(
    r"^(?:[*x.\-_]+|null|none|true|false|undefined|n/?a|required|optional)$", re.I
)
_DEV_NOTE = re.compile(
    r"\b(?:TODO|FIXME|HACK|XXX|BUG)\b|(?i:\b(?:remove (?:this|before)|temporary|temp fix|"
    r"do not (?:deploy|commit|ship)|debug(?:ging)? only|test(?:ing)? only|dev(?:elopment)? only|"
    r"workaround)\b)"
)
INTERNAL_HOST = re.compile(
    r"(?:(?<=//)|(?<=@)|(?<=[\"'\s(]))((?:[a-z0-9-]+\.)+(?:local|internal|intranet|corp|lan|"
    r"localdomain|home\.arpa|priv|private))(?=[:/\"'\s)]|$)",
    re.I,
)
LOCAL_URL = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d+)?[^\s\"'<>`)]*",
    re.I,
)
_EMAIL = re.compile(
    # Not after ":" or "/" (URL userinfo like scheme://user:pass@host), except mailto:.
    r"(?:(?<=mailto:)|(?<![\w.%+:/-]))"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}\b"
)
_EMAIL_IGNORE = re.compile(
    r"\.(?:png|jpe?g|gif|svg|webp|avif)$|@(?:example\.(?:com|org|net)|domain\.com|email\.com|"
    r"yourdomain\.\w+|sentry\.io|[\w.-]*\.ingest\.sentry\.io)$",
    re.I,
)
_API = re.compile(
    r"[\"'`]((?:https?://[\w.-]+(?::\d+)?)?/(?:api|graphql|rest|services|v[1-9]\d?)(?:[/?][^\"'`\s<>]*)?)[\"'`]"
)
_STATIC_EXT = re.compile(r"\.(?:js|mjs|css|png|jpe?g|gif|svg|webp|ico|woff2?|map)(?:\?|$)", re.I)
_SENSITIVE_PATH = re.compile(
    r"(?i)(?:^|/)(?:admin\w*|administrator|backups?\w*|bak|old|dev|staging|stage|tests?|internal|"
    r"private|secrets?|config\w*|conf|\.git|\.svn|\.env|\.htpasswd|\.ds_store|db|database|sql|"
    r"dumps?|phpmyadmin|wp-admin|cgi-bin|debug|logs?|tmp|temp|install\w*|setup|console|"
    r"actuator|server-status|_profiler)(?=/|\.|$|\?)"
    r"|\.(?:sql|bak|old|orig|swp|zip|tar|gz|tgz|7z|rar|env|ini|conf|cfg|log|key|pem|p12|pfx|"
    r"db|sqlite3?)$"
)


# --- helpers ------------------------------------------------------------------------------


def _clip(s: str, limit: int = 160) -> str:
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= limit else s[:limit] + "..."


def _snippet(text: str, m: re.Match[str], before: int = 40, after: int = 120) -> str:
    return _clip(text[max(0, m.start() - before) : m.end() + after])


def visible_text(html: str, *, strip_code: bool) -> str:
    """Rendered-ish text of an HTML document, optionally without code/quote blocks."""
    tree = LexborHTMLParser(html)
    for tag in _NON_TEXT_TAGS + (_CODE_TAGS if strip_code else ()):
        for node in tree.css(tag):
            node.decompose()
    root = tree.body or tree.root
    return root.text(separator="\n") if root else ""


def _scan_text(resp: CollectedResponse) -> tuple[str, Confidence]:
    """Text to search for traces/errors/paths, and how sure a hit is."""
    error = resp.status >= 400
    if resp.content_type in _HTML:
        return visible_text(resp.text, strip_code=not error), C.HIGH if error else C.MEDIUM
    return resp.text, C.HIGH if error else C.MEDIUM


def _comments(html: str) -> list[str]:
    """HTML comments plus block/line comments inside inline scripts."""
    out = [
        c
        for c in re.findall(r"<!--([\s\S]*?)-->", html)
        if not re.match(r"\s*\[if|\s*<!\[endif", c)
    ]
    tree = LexborHTMLParser(html)
    for node in tree.css("script"):
        if node.attributes.get("src"):
            continue
        code = node.text() or ""
        out += [c for c in re.findall(r"/\*([\s\S]*?)\*/", code) if not c.startswith("!")]
        out += re.findall(r"(?m)^\s*//(.*)$", code)
    return out


def is_lab_host(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


def _finding(
    resp: CollectedResponse,
    fid: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    evidence: Sequence[Evidence],
    impact: str,
    fix: str,
    refs: tuple[str, ...],
) -> Finding:
    return Finding(
        fid, title, severity, confidence, (resp.url,), tuple(evidence), impact, fix, refs
    )


# --- page checks --------------------------------------------------------------------------


def check_debug_and_errors(resp: CollectedResponse) -> list[Finding]:
    """Framework debug pages, stack traces, DB errors, server paths (one family per page)."""
    if not resp.text or resp.content_type not in _BODY_TYPES:
        return []
    text, conf = _scan_text(resp)
    traces = [(lang, rx) for lang, rx, n in _TRACES if len(rx.findall(text)) >= n]
    out: list[Finding] = []

    debug = next(
        ((n, rx) for n, rx in _DEBUG_PAGES if resp.content_type in _HTML and rx.search(resp.text)),
        None,
    )
    if debug:
        name, rx = debug
        m = rx.search(resp.text)
        ev = [Evidence("body", _snippet(resp.text, m) if m else name, "debug marker")]
        if traces:
            lang, trx = traces[0]
            tm = trx.search(text)
            ev.append(
                Evidence("body", _snippet(text, tm, 0) if tm else lang, f"{lang} stack trace")
            )
        out.append(
            _finding(
                resp,
                "DISC-DEBUG-PAGE",
                f"Framework debug/error page exposed: {name}",
                S.MEDIUM if traces else S.LOW,
                C.HIGH,
                ev,
                "Debug output reveals code, stack frames, file paths, settings, sometimes secrets.",
                "Disable debug mode in production and serve a generic error page.",
                ("CWE-215", "CWE-209", A05),
            )
        )
    else:
        for lang, trx in traces[:1]:
            m = trx.search(text)
            out.append(
                _finding(
                    resp,
                    "DISC-STACK-TRACE",
                    f"Stack trace exposed ({lang})",
                    S.LOW,
                    conf,
                    [Evidence("body", _snippet(text, m, 0) if m else lang, f"{lang} stack trace")],
                    "Stack traces reveal code structure, libraries and file paths.",
                    "Catch errors and return a generic message; log details server-side.",
                    ("CWE-209", A05),
                )
            )
        paths = list(dict.fromkeys(_SERVER_PATH.findall(text)))[:MAX_ITEMS]
        if paths:
            out.append(
                _finding(
                    resp,
                    "DISC-SERVER-PATH",
                    "Absolute server file path disclosed",
                    S.LOW,
                    conf,
                    [Evidence("body", p, "path") for p in paths],
                    "Server paths reveal OS, deployment layout and usernames.",
                    "Suppress error details (e.g. PHP display_errors=Off) in production.",
                    ("CWE-209", A05),
                )
            )

    seen_db: set[str] = set()
    for name, rx in _DB_ERRORS:
        m = rx.search(text)
        if m and name not in seen_db:
            seen_db.add(name)
            out.append(
                _finding(
                    resp,
                    "DISC-DB-ERROR",
                    f"Database error message exposed ({name})",
                    S.MEDIUM,
                    conf,
                    [Evidence("body", _snippet(text, m), "database error")],
                    "Raw DB errors reveal schema/queries and are a classic injection signal.",
                    "Return a generic error; log the DB error server-side.",
                    ("CWE-209", "CWE-89", A05),
                )
            )
    return out


def check_directory_listing(resp: CollectedResponse) -> list[Finding]:
    """Auto-generated directory index pages (met via normal links only)."""
    if resp.status != 200 or resp.content_type not in _HTML:
        return []
    for name, rx in _LISTINGS:
        if m := rx.search(resp.text):
            return [
                _finding(
                    resp,
                    "DISC-DIR-LISTING",
                    "Directory listing enabled",
                    S.LOW,
                    C.HIGH,
                    [Evidence("body", _snippet(resp.text, m, 0, 60), name)],
                    "Visitors can browse every file in the directory, including ones not linked.",
                    "Disable auto-indexing (Apache Options -Indexes; nginx autoindex off).",
                    ("CWE-548", A05),
                )
            ]
    return []


def _mask(value: str) -> str:
    return f"<masked, {len(value)} chars>"


def check_comments(resp: CollectedResponse) -> list[Finding]:
    """Credential-looking values and developer notes in HTML/inline-script comments."""
    if resp.content_type not in _HTML or not resp.text:
        return []
    creds: list[Evidence] = []
    notes: list[Evidence] = []
    for comment in _comments(resp.text):
        masked = comment
        hit = False
        for m in _URL_CRED.finditer(comment):
            masked = masked.replace(m.group(0), m.group(1) + _mask(m.group(2)) + m.group(3))
            hit = True
        for m in _CRED.finditer(comment):
            value = m.group(2)
            if (
                _PLACEHOLDER.match(value)
                or value[0] in "{$<%("
                or "(" in value
                or "process.env" in value
            ):
                continue
            masked = masked.replace(value, _mask(value))
            hit = True
        if hit:
            creds.append(Evidence("comment", _clip(masked), "comment"))
        elif _DEV_NOTE.search(comment):
            notes.append(Evidence("comment", _clip(comment), "comment"))
    out = []
    if creds:
        out.append(
            _finding(
                resp,
                "DISC-CREDENTIAL-COMMENT",
                "Comment appears to contain credentials",
                S.MEDIUM,
                C.MEDIUM,
                creds[:MAX_ITEMS],
                "Anyone viewing the page source can read the credential (values masked here).",
                "Remove the comment, rotate the credential, and strip comments at build time.",
                ("CWE-615", "CWE-798", A05),
            )
        )
    if notes:
        out.append(
            _finding(
                resp,
                "DISC-DEV-COMMENT",
                "Developer notes in page source",
                S.INFO,
                C.MEDIUM,
                notes[:MAX_ITEMS],
                "Notes can hint at unfinished or weak areas of the application.",
                "Strip comments from production builds.",
                ("CWE-615",),
            )
        )
    return out


def check_source_leaks(resp: CollectedResponse) -> list[Finding]:
    """Internal hostnames/local URLs, email addresses, and API endpoints in page source."""
    if resp.content_type not in _HTML or not resp.text:
        return []
    src = resp.text
    out = []
    if not is_lab_host(resp.url):
        hosts = dict.fromkeys(
            [m.group(1).lower() for m in INTERNAL_HOST.finditer(src)] + LOCAL_URL.findall(src)
        )
        if hosts:
            out.append(
                _finding(
                    resp,
                    "DISC-INTERNAL-HOST",
                    "Internal hostnames or local URLs in page source",
                    S.LOW,
                    C.MEDIUM,
                    [Evidence("body", h, "reference") for h in list(hosts)[:MAX_ITEMS]],
                    "Reveals internal infrastructure names and dev/staging leftovers.",
                    "Remove internal references from client-side code and markup.",
                    ("CWE-200",),
                )
            )
    emails = [e for e in dict.fromkeys(_EMAIL.findall(src)) if not _EMAIL_IGNORE.search(e)]
    if emails:
        out.append(
            _finding(
                resp,
                "DISC-EMAIL",
                "Email addresses in page source",
                S.INFO,
                C.HIGH,
                [Evidence("body", e, "email") for e in emails[:MAX_ITEMS]],
                "Harvestable for spam/phishing; may expose staff or internal addresses.",
                "Publish role addresses only; consider a contact form for the rest.",
                ("CWE-200",),
            )
        )
    apis = [a for a in dict.fromkeys(_API.findall(src)) if not _STATIC_EXT.search(a)]
    if apis:
        out.append(
            _finding(
                resp,
                "DISC-API-ENDPOINT",
                "API endpoints referenced in page source",
                S.INFO,
                C.HIGH,
                [Evidence("body", a, "endpoint") for a in apis[:MAX_ITEMS]],
                "Informational: maps the API surface (reported only, never fetched).",
                "None required; ensure each endpoint enforces authorization.",
                ("CWE-200",),
            )
        )
    return out


# --- robots.txt / sitemap -----------------------------------------------------------------


def check_robots(resp: CollectedResponse) -> list[Finding]:
    """Sensitive-looking paths named in robots.txt (reported, never fetched)."""
    if resp.status != 200 or resp.content_type in _HTML:
        return []
    paths = []
    for line in resp.text.splitlines():
        key, _, value = line.partition(":")
        value = value.split("#")[0].strip()
        if key.strip().lower() in {"disallow", "allow"} and value and _SENSITIVE_PATH.search(value):
            paths.append(value)
    if not paths:
        return []
    return [
        _finding(
            resp,
            "DISC-ROBOTS-SENSITIVE",
            "robots.txt names sensitive-looking paths",
            S.INFO,
            C.MEDIUM,
            [
                Evidence("robots", p, "Disallow/Allow")
                for p in list(dict.fromkeys(paths))[:MAX_ITEMS]
            ],
            "robots.txt is public; listing a path advertises it (Albert did not fetch these).",
            "Protect sensitive areas with authentication, not robots.txt.",
            ("CWE-200",),
        )
    ]


def check_sitemap(resp: CollectedResponse) -> list[Finding]:
    """Sensitive-looking URLs listed in a sitemap."""
    if resp.status != 200 or not re.search(r"<(?:urlset|sitemapindex)\b", resp.text[:2000]):
        return []
    locs = [m.strip() for m in re.findall(r"<loc>\s*(.*?)\s*</loc>", resp.text, re.S)]
    hits = [u for u in locs if _SENSITIVE_PATH.search(urlsplit(u).path)]
    if not hits:
        return []
    return [
        _finding(
            resp,
            "DISC-SITEMAP-SENSITIVE",
            "Sitemap lists sensitive-looking URLs",
            S.INFO,
            C.MEDIUM,
            [Evidence("sitemap", u, "loc") for u in list(dict.fromkeys(hits))[:MAX_ITEMS]],
            "Sitemaps are public; staging/admin/backup URLs in them are easy to find.",
            "Keep non-public URLs out of sitemaps and protect them with authentication.",
            ("CWE-200",),
        )
    ]


def check_disclosure(resp: CollectedResponse) -> list[Finding]:
    """Route one response to the checks that apply."""
    path = urlsplit(resp.url).path
    if path == "/robots.txt":
        return check_robots(resp)
    if resp.text[:2000].lstrip().startswith("<?xml") or path.endswith(".xml"):
        return check_sitemap(resp)
    return (
        check_debug_and_errors(resp)
        + check_directory_listing(resp)
        + check_comments(resp)
        + check_source_leaks(resp)
    )


def run_disclosure_checks(responses: Sequence[CollectedResponse]) -> list[Finding]:
    """Family entry point: pages plus robots.txt/sitemaps, grouped across pages."""
    return group_findings(f for r in responses for f in check_disclosure(r))
