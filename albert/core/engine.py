"""Runs check families over already-collected data. YAML rules join in step 13."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence

from albert.checks.cookies import run_cookie_checks
from albert.checks.cors import run_cors_checks
from albert.checks.disclosure import run_disclosure_checks
from albert.checks.headers import run_header_checks
from albert.checks.security_txt import run_security_txt_checks
from albert.core.models import CollectedResponse, Finding, ScanResult

CheckFamily = Callable[[Sequence[CollectedResponse]], list[Finding]]

FAMILIES: dict[str, CheckFamily] = {
    "headers": run_header_checks,
    "cookies": run_cookie_checks,
    "cors": run_cors_checks,
    "disclosure": run_disclosure_checks,
    "security_txt": run_security_txt_checks,
}


def run_checks(
    result: ScanResult,
    responses: Sequence[CollectedResponse],
    families: Iterable[str] | None = None,
) -> None:
    """Run the named families (default: all) and record findings + checks run on ``result``."""
    for name in families or FAMILIES:
        result.findings.extend(FAMILIES[name](responses))
        result.checks_run.append(name)
