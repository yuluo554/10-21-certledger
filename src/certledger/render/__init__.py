"""Report rendering: JSON + Markdown from one in-memory model.

Rendering performs **no judgement** (``plan/03`` §④ 渲染三律): this package does
not import ``certledger.hygiene`` — an AST gate asserts it — and it does not
decide whether anything is wrong. It is handed a findings document that has
already been produced, and its whole job is to lay that document out twice, in
one order, and to turn an already-computed severity into a process exit code.

What it does own:

* the **report document** — the keys, their order, and the baseline diff;
* the **exit-code threshold** (``--fail-on``): 1 is produced here and nowhere
  else, and ``none`` means 0 while still printing every finding;
* **masking** of absolute paths, for both formats, from one place;
* **``--top``**, which trims the expiry *table* — never the findings.

JSON and Markdown are rendered from the same dict, so they cannot disagree about
what was found; a second run over the same input and the same ``--as-of``
produces the same bytes in both formats.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from certledger import __version__
from certledger.errors import EXIT_OK, EXIT_THRESHOLD, CliError
from certledger.model import SCHEMA_VERSION, SEVERITY_ORDER, dump_json
from certledger.render.markdown_out import render_markdown
from certledger.render.redact import redact_absolutes

#: A stored report declares this ``kind``; a baseline that does not is refused
#: rather than diffed into nonsense.
REPORT_KIND = "report"

#: ``--fail-on`` accepts the three severities plus the switch that turns gating
#: off entirely (``plan/03`` §④ 退出码).
FAIL_ON_VALUES = ("ERROR", "WARN", "INFO", "none")


def render(
    *,
    findings_document: dict,
    ledger: dict,
    policy,
    fail_on: str | None,
    top: int | None,
    redact: bool,
    json_path: str | None,
    markdown_path: str | None,
    baseline: str | None,
) -> int:
    """Render the report and return its exit code.

    ``findings_document`` is the output of one ``hygiene.evaluate`` pass; it is
    passed in rather than produced here, which is what keeps this package free of
    judgement. The ledger rides along because the baseline diff is about
    *certificates*, and a findings list alone cannot tell a re-signed certificate
    from a new one.
    """
    if findings_document is None or policy is None:
        raise CliError("报告缺输入", "render 需要 findings 文档与已加载的策略文件")

    threshold = _threshold(fail_on, policy)
    document = _build_document(
        findings_document=findings_document,
        ledger=ledger,
        threshold=threshold,
        top=top,
        baseline=baseline,
    )
    exit_code = _exit_code(document["findings"], threshold)
    document["exit_code"] = exit_code

    if redact:
        document = redact_absolutes(document)

    _write(json_path, markdown_path, document)
    return exit_code


# ── the document ────────────────────────────────────────────────────────────


def _build_document(
    *,
    findings_document: dict,
    ledger: dict,
    threshold: str,
    top: int | None,
    baseline: str | None,
) -> dict[str, Any]:
    """Assemble the report. Key order is declared here and never sorted (K5).

    ``certificates`` is not decoration: it is the material a *later* run needs to
    answer "what changed". A report that only carried findings could never say
    that a certificate was re-signed with the same key but a new validity
    period, because the SPKI is not part of any finding.
    """
    findings = list(findings_document.get("findings") or [])
    certificates = _certificates(ledger)
    expiries = _expiries(findings)
    shown = expiries[:top] if top is not None and top >= 0 else expiries

    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "kind": REPORT_KIND,
        "tool_version": __version__,
        "as_of": findings_document["as_of"],
        "as_of_utc": findings_document["as_of_utc"],
        "policy_version": findings_document["policy_version"],
        "policy_sha256": findings_document["policy_sha256"],
        "fail_on": threshold,
        "exit_code": EXIT_OK,  # replaced once the threshold has been applied
        "summary": {
            **_summary_of(findings_document),
            "certificates": len(certificates),
            "expiries_total": len(expiries),
            "expiries_shown": len(shown),
        },
        "certificates": certificates,
        "findings": findings,
        "expiries": shown,
    }
    if baseline:
        document["diff"] = _diff_against(baseline, certificates)
    return document


def _summary_of(findings_document: dict) -> dict[str, Any]:
    """The judgement's own counters, carried through unchanged.

    Copied verbatim from the findings document rather than recomputed: a report
    that counted findings a second time would eventually disagree with the
    document it claims to summarise, and the disagreement would surface in the
    one place nobody diffs.
    """
    summary = findings_document.get("summary") or {}
    return {
        "records": summary.get("records", {}),
        "findings": summary.get("findings", 0),
        "by_severity": summary.get("by_severity", {}),
        "suppressed": summary.get("suppressed", 0),
        "suppressed_by_code": summary.get("suppressed_by_code", {}),
    }


def _certificates(ledger: dict) -> list[dict[str, Any]]:
    """One identity row per certificate: the baseline's input.

    Carries the display subject **and** its DER hash: two certificates can render
    an identical subject string while being different names, and grouping a
    rotation on the display string would pair them.
    """
    rows: list[dict[str, Any]] = []
    for record in ledger.get("certs") or []:
        if not isinstance(record, dict):
            continue
        subject = record.get("subject")
        display = subject.get("display", "") if isinstance(subject, dict) else str(subject or "")
        der_hash = subject.get("der_sha256", "") if isinstance(subject, dict) else ""
        rows.append(
            {
                "fingerprint_sha256": str(record.get("fingerprint_sha256", "")),
                "spki_sha256": str(record.get("spki_sha256", "")),
                "subject": display,
                "subject_der_sha256": der_hash,
            }
        )
    return sorted(rows, key=lambda row: row["fingerprint_sha256"])


def _expiries(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The expiry table's rows: ``EXPIRED`` / ``EXPIRING``, soonest first.

    ``not_after`` ascending is the order ``plan/03`` §③ 过期表 declares. The rows
    are derived from findings — never from the ledger — so the table cannot list
    a certificate the verdict did not mention.
    """
    rows: list[dict[str, Any]] = []
    for finding in findings:
        if finding.get("code") not in ("EXPIRED", "EXPIRING"):
            continue
        evidence = finding.get("evidence") or {}
        days = (
            evidence.get("days_over")
            if finding.get("code") == "EXPIRED"
            else evidence.get("days_left")
        )
        rows.append(
            {
                "not_after": str(evidence.get("not_after", "")),
                "state": finding["code"],
                "days": days,
                "subject": finding.get("subject", ""),
                "fingerprint": finding.get("fingerprint", ""),
            }
        )
    return sorted(rows, key=lambda row: (row["not_after"], row["fingerprint"]))


# ── exit-code threshold ─────────────────────────────────────────────────────


def _threshold(fail_on: str | None, policy) -> str:
    """``--fail-on``, or the policy's ``report.default_fail_on``.

    No default literal in code (K3): the fallback is read from the policy file,
    which the loader has already validated against the same four values.
    """
    value = fail_on or str(policy.require("report.default_fail_on"))
    if value not in FAIL_ON_VALUES:
        raise CliError("--fail-on 非法", f"必须是 {' / '.join(FAIL_ON_VALUES)} 之一，收到 {value!r}")
    return value


def _exit_code(findings: list[dict[str, Any]], threshold: str) -> int:
    """1 when a finding reaches the threshold, 0 otherwise (``none`` is always 0).

    ``none`` suppresses the *gate*, not the findings: every finding is still
    rendered, because "do not fail my build" and "do not tell me what you found"
    are different requests and only one of them was made.
    """
    if threshold == "none":
        return EXIT_OK
    limit = SEVERITY_ORDER[threshold]
    for finding in findings:
        rank = SEVERITY_ORDER.get(str(finding.get("severity", "")), 99)
        if rank <= limit:
            return EXIT_THRESHOLD
    return EXIT_OK


# ── baseline ────────────────────────────────────────────────────────────────


def _diff_against(baseline: str, certificates: list[dict[str, Any]]) -> dict[str, Any]:
    """``added`` / ``removed`` / ``rotated`` against a stored report.

    A certificate is **rotated** when the same name is carried by the same public
    key under a new fingerprint: the key survived, the certificate did not — a
    re-signing, which is what a renewal usually is. When the key changes too, the
    pair is ``removed`` + ``added`` and is *not* called a rotation: the two
    certificates share nothing but a string (``plan/03`` §④).

    Pairing is on ``(subject_der_sha256, spki_sha256)``, not on the display
    subject: display strings collide, DER names do not.
    """
    previous = _read_report(baseline)
    before = [_as_certificate_row(row) for row in previous.get("certificates") or []]
    after = certificates

    before_by_fingerprint = {row["fingerprint_sha256"]: row for row in before}
    after_by_fingerprint = {row["fingerprint_sha256"]: row for row in after}

    added = [
        row for fingerprint, row in sorted(after_by_fingerprint.items())
        if fingerprint not in before_by_fingerprint
    ]
    removed = [
        row for fingerprint, row in sorted(before_by_fingerprint.items())
        if fingerprint not in after_by_fingerprint
    ]

    rotated: list[dict[str, Any]] = []
    removed_left: list[dict[str, Any]] = []
    added_used: set[str] = set()

    removed_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in removed:
        removed_groups.setdefault((row["subject_der_sha256"], row["spki_sha256"]), []).append(row)
    added_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in added:
        added_groups.setdefault((row["subject_der_sha256"], row["spki_sha256"]), []).append(row)

    for group in sorted(removed_groups):
        gone = removed_groups[group]
        fresh = added_groups.get(group) or []
        if not fresh:
            removed_left.extend(gone)
            continue
        # Same name, same key, new fingerprint ⇒ one rotation per pairing. The
        # shorter side is paired and the surplus falls back to added/removed, so
        # nothing is ever silently dropped from the diff.
        for old_row, new_row in zip(gone, fresh):
            rotated.append(
                {
                    "subject": new_row["subject"],
                    "subject_der_sha256": new_row["subject_der_sha256"],
                    "spki_sha256": new_row["spki_sha256"],
                    "from": old_row["fingerprint_sha256"],
                    "to": new_row["fingerprint_sha256"],
                }
            )
            added_used.add(new_row["fingerprint_sha256"])
        # Surplus certificates on either side stay in ``added`` / ``removed``:
        # every certificate that appeared or vanished is reported exactly once.
        removed_left.extend(gone[len(fresh) :])

    added_left = [row for row in added if row["fingerprint_sha256"] not in added_used]

    return {
        "added": added_left,
        "removed": sorted(removed_left, key=lambda row: row["fingerprint_sha256"]),
        "rotated": sorted(rotated, key=lambda row: (row["subject_der_sha256"], row["to"])),
    }


def _as_certificate_row(row: Any) -> dict[str, Any]:
    """One identity row from a stored report, with the fields the diff needs.

    Missing fields become empty strings rather than raising: a baseline written
    by an older build should degrade to "cannot match this one", not abort the
    run. An empty ``subject_der_sha256`` simply never groups with anything.
    """
    if not isinstance(row, dict):
        return {"fingerprint_sha256": "", "spki_sha256": "", "subject": "", "subject_der_sha256": ""}
    return {
        "fingerprint_sha256": str(row.get("fingerprint_sha256", "")),
        "spki_sha256": str(row.get("spki_sha256", "")),
        "subject": str(row.get("subject", "")),
        "subject_der_sha256": str(row.get("subject_der_sha256", "")),
    }


def _read_report(path: str) -> dict[str, Any]:
    """A stored report, or an input error (exit 2).

    A baseline that is missing, is not JSON, or is a different document is not a
    licence to diff against an empty report — that would print every certificate
    as "added" and call it a finding.
    """
    target = Path(path)
    if not target.is_file():
        raise CliError("基线文件不存在", path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except OSError as error:
        raise CliError("基线文件不可读", f"{target.name}: {error.strerror}") from None
    except json.JSONDecodeError as error:
        raise CliError("基线文件不是合法 JSON", f"{target.name}: {error}") from None
    if not isinstance(payload, dict) or payload.get("kind") != REPORT_KIND:
        raise CliError(
            "基线文件类型不符",
            f"{target.name} 的 kind 应为 {REPORT_KIND}，收到 "
            f"{payload.get('kind') if isinstance(payload, dict) else type(payload).__name__}",
        )
    return payload


# ── output ──────────────────────────────────────────────────────────────────


def _write(json_path: str | None, markdown_path: str | None, document: dict[str, Any]) -> None:
    """Write the two formats, or one of them to stdout.

    With neither flag the JSON goes to stdout, matching every other subcommand:
    one machine-readable document is the default answer. Naming only
    ``--markdown`` writes only the Markdown — asking for one format must not
    leave a second document on the console.
    """
    json_target = json_path if json_path is not None else ("-" if markdown_path is None else None)

    if json_target is not None:
        _emit(json_target, dump_json(document), "wrote")
    if markdown_path is not None:
        _emit(markdown_path, render_markdown(document), "wrote")


def _emit(target: str, text: str, verb: str) -> None:
    import sys

    if target == "-":
        sys.stdout.write(text)
        return
    path = Path(target)
    try:
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as error:
        raise CliError("输出不可写", f"{target}: {error.strerror}") from None
    sys.stdout.write(f"{verb} {target}\n")


__all__ = ["FAIL_ON_VALUES", "REPORT_KIND", "render"]
