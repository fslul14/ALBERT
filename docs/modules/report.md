# core/report.py: Markdown + JSON reports

One sanitized dict feeds both formats (JSON mirrors MD). Every string is swept with
`secrets.redact` before writing, and the rendered Markdown is swept again (redaction backstop),
independent of check-side redaction. Untrusted values are rendered in code spans.

Sections: Header, Executive summary, Changes since last scan (`--diff`), Findings (Low+),
Posture notes (Info), Appendix (pages, skipped, blocked, technologies, errors).

## Posture grade

Over grouped findings, Info excluded:

- **Weights:** Critical 40, High 25, Medium 10, Low 3 (the most one finding can cost).
- **Diminishing repeats:** within a severity, findings are ordered by confidence and the k-th
  costs `weight x confidence x 0.5^k`. A severity therefore costs at most 2x its weight, so
  twenty Lows (< 6 points) never outweigh one High (25).
- **Confidence factor:** High 1.0, Medium 0.75, Low 0.5.
- **Caps:** any Critical at Medium+ confidence limits the grade to D, any High to C, whatever
  the score.
- **Grades:** A >= 92, B >= 80, C >= 65, D >= 50, else F. The JSON records `score`, `grade`,
  `capped_by` and per-severity `penalties`.

Sanity (tests): the hardened header fixture is 100/A, the bare-Apache and weak fixtures are
75 and 77 (C), and one High is 75 (C).
