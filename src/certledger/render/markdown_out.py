"""Markdown rendering of a report document: the human-readable half.

Three rules, and each exists because the obvious alternative is worse
(``plan/03`` §④ 渲染三律):

1. **One source, two formats.** This module is handed the *finished* report
   document — the same dict the JSON writer serialises. It decides nothing: it
   does not sort, threshold, truncate or re-count. If the two formats could
   disagree, one of them would be wrong, and nothing would say which.
2. **No external links.** Not one ``http(s)://`` in the body. Citations appear as
   text (``RFC 5280 4.1.2.5``), because a report is read offline, in a diff, or
   from an attachment — and a link in a report is also a small outbound fetch
   that the tool's own privacy statement says does not happen. A certificate's
   *name* is data, though, and a real one can carry a URL (the trust-store root
   whose subject reads ``CN=http://www.usertrust.com``); such a value is escaped
   by ``_cell`` rather than allowed to become a link, so the rule holds for the
   body while the data stays legible.
3. **The findings table has one row per finding.** No truncation, no "top 10".
   ``--top`` limits the *expiry table*, which is a presentation aid; the findings
   table is the verdict, and a verdict that depends on a flag is not a verdict.
"""

from __future__ import annotations

from typing import Any

#: Column headers, in the order the tables are written. Named constants so the
#: row builder and the test that counts columns cannot drift apart silently.
#:
#: ``location`` is the finding's ``evidence.path``, already masked. Without it a
#: diagnostic finding renders as a row of empty cells — code and citation with no
#: indication of *which* file it came from — which is the one thing that makes
#: such a finding actionable. It is the only evidence field the table shows, and
#: it is drawn from the document rather than from the filesystem, so masking has
#: already been applied to it.
FINDING_COLUMNS = ("severity", "code", "subject", "location", "fingerprint", "rule_source")
EXPIRY_COLUMNS = ("not_after", "state", "days", "subject", "fingerprint")
CERTIFICATE_COLUMNS = ("fingerprint_sha256", "subject")


def render_markdown(document: dict[str, Any]) -> str:
    """Render one report document as Markdown (trailing newline included)."""
    lines: list[str] = ["# CertLedger report", ""]

    lines += _header(document)
    lines += _summary(document)
    lines += _findings(document)
    lines += _expiries(document)
    lines += _diff(document)

    text = "\n".join(lines).rstrip("\n") + "\n"
    # A link would be a network fetch waiting to happen, and the tool advertises
    # itself as offline. Values that carry a URL are defused by ``_cell``, so this
    # fires only if something *else* smuggled one in — a citation added to the
    # policy file, say. Checked here as well as in the tests: a citation added
    # to the policy file must not be able to smuggle one in.
    if "http://" in text or "https://" in text:
        raise ValueError("报告正文出现外链：报告层不得引入网络引用（plan/03 §④ 渲染三律）")
    return text


def _header(document: dict[str, Any]) -> list[str]:
    """Echo the facts a reader needs to reproduce the verdict (``plan/03`` §④).

    ``as_of`` is echoed **as it was typed** alongside the canonical UTC form: the
    raw spelling is what the user can paste back into a command line, and the
    UTC form is what the comparisons actually used.
    """
    rows = [
        ("as_of", f"{document['as_of']} ({document['as_of_utc']})"),
        ("tool_version", document["tool_version"]),
        ("schema_version", document["schema_version"]),
        ("policy_version", document["policy_version"]),
        ("policy_sha256", document["policy_sha256"]),
        ("fail_on", document["fail_on"]),
        ("exit_code", document["exit_code"]),
    ]
    lines = [f"- **{name}**: `{value}`" for name, value in rows]
    lines.append("")
    return lines


def _summary(document: dict[str, Any]) -> list[str]:
    summary = document["summary"]
    lines = ["## Summary", "", "| unit | value |", "| --- | --- |"]
    lines.append(f"| findings | {summary['findings']} |")
    for severity, count in summary["by_severity"].items():
        lines.append(f"| findings ({severity}) | {count} |")
    lines.append(f"| records (certs) | {summary['records']['certs']} |")
    lines.append(f"| records (keys) | {summary['records']['keys']} |")
    lines.append(f"| records (diagnostics) | {summary['records']['diagnostics']} |")
    lines.append(f"| suppressed (level: off) | {summary['suppressed']} |")
    lines.append(f"| certificates | {summary['certificates']} |")
    lines.append(f"| expiries shown / total | {summary['expiries_shown']} / {summary['expiries_total']} |")
    lines.append("")
    return lines


def _findings(document: dict[str, Any]) -> list[str]:
    findings = document["findings"]
    lines = [f"## Findings ({len(findings)})", ""]
    if not findings:
        lines += ["No rule fired at this instant.", ""]
        return lines
    lines.append("| " + " | ".join(FINDING_COLUMNS) + " |")
    lines.append("| " + " | ".join("---" for _ in FINDING_COLUMNS) + " |")
    for finding in findings:
        lines.append("| " + " | ".join(_finding_cells(finding)) + " |")
    lines.append("")
    return lines


def _finding_cells(finding: dict[str, Any]) -> list[str]:
    """One finding, as cells in ``FINDING_COLUMNS`` order."""
    evidence = finding.get("evidence") or {}
    values = {
        "severity": finding.get("severity"),
        "code": finding.get("code"),
        "subject": finding.get("subject"),
        "location": evidence.get("path"),
        "fingerprint": finding.get("fingerprint"),
        "rule_source": finding.get("rule_source"),
    }
    return [_cell(values.get(column)) for column in FINDING_COLUMNS]


def _expiries(document: dict[str, Any]) -> list[str]:
    """The display aid. Truncated by ``--top``, and labelled as such."""
    expiries = document["expiries"]
    total = document["summary"]["expiries_total"]
    lines = [f"## Expiries ({len(expiries)} of {total})", ""]
    if not expiries:
        return lines
    lines.append("| " + " | ".join(EXPIRY_COLUMNS) + " |")
    lines.append("| " + " | ".join("---" for _ in EXPIRY_COLUMNS) + " |")
    for item in expiries:
        lines.append(
            "| " + " | ".join(_cell(item.get(column)) for column in EXPIRY_COLUMNS) + " |"
        )
    lines.append("")
    return lines


def _diff(document: dict[str, Any]) -> list[str]:
    diff = document.get("diff")
    if not diff:
        return []
    lines = ["## Diff against baseline", ""]
    for label, key in (("Added", "added"), ("Removed", "removed")):
        rows = diff.get(key) or []
        lines.append(f"### {label} ({len(rows)})")
        lines.append("")
        if rows:
            lines.append("| " + " | ".join(CERTIFICATE_COLUMNS) + " |")
            lines.append("| " + " | ".join("---" for _ in CERTIFICATE_COLUMNS) + " |")
            for row in rows:
                lines.append(
                    "| "
                    + " | ".join(_cell(row.get(column)) for column in CERTIFICATE_COLUMNS)
                    + " |"
                )
        lines.append("")

    rotated = diff.get("rotated") or []
    lines.append(f"### Rotated ({len(rotated)})")
    lines.append("")
    if rotated:
        columns = ("subject", "spki_sha256", "from", "to")
        lines.append("| " + " | ".join(columns) + " |")
        lines.append("| " + " | ".join("---" for _ in columns) + " |")
        for row in rotated:
            lines.append("| " + " | ".join(_cell(row.get(column)) for column in columns) + " |")
        lines.append("")
    return lines


def _cell(value: Any) -> str:
    """One table cell: never a line break, never an empty column, never a pipe,
    never a link.

    A raw ``|`` or newline inside a value would break the table and silently
    change the row count — which is exactly what the "one row per finding" rule
    is asserted with. A raw ``http(s)://`` inside a value would be turned into a
    clickable link by any GFM reader, and this tool is offline by design; a
    certificate *name* can carry a URL (a real trust-store root reads
    ``CN=http://www.usertrust.com``), so the value is escaped rather than dropped.
    """
    if value is None:
        return ""
    text = str(value).replace("|", "\\|")
    text = " ".join(text.split())
    return _defuse(text)


#: Each ``http(s)://`` in a rendered value gets a backslash before its colon. The
#: body then contains no ``http(s)://`` substring at all — which is 渲染三律 2
#: asserted literally, not merely "no Markdown link syntax" — while a human still
#: reads ``http://``: CommonMark unescapes ``\\:`` back to ``:``, and the escape
#: also stops a GFM reader from linkifying the value.
_LINK_DEFUSED = (("http://", "http\\://"), ("https://", "https\\://"))


def _defuse(text: str) -> str:
    """Make a value unable to become an external link in the rendered body."""
    for needle, replacement in _LINK_DEFUSED:
        text = text.replace(needle, replacement)
    return text


__all__ = ["render_markdown"]
