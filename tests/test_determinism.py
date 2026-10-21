"""Deterministic reports: same input, same ``--as-of``, same bytes.

``plan/00`` 招牌动词表 names this file, and the claim it is written against is
narrower than "the output looks the same":

* both formats must be **byte-identical** between two runs — comparing parsed
  dicts would hide key-order changes, and key order is part of the contract
  (``plan/00`` D9);
* the ``sha256`` of the two Markdown files must be equal for the same reason;
* the walk order must not reach the output: a report over ``left, right`` and one
  over ``right, left`` are the same document;
* ``--top`` may trim the expiry *table* and must not touch the findings or the
  exit code (``plan/03`` §③ 过期表: 截断门禁 = CI 后门);
* nothing volatile — no timestamp, no duration, no host name, no user name — may
  appear in either format (``plan/00`` D9).

The inputs are built here rather than taken from ``fixtures/out``, so these
assertions run in CI, which generates no fixtures.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from pathlib import Path

import pytest

from certledger.pipeline import report

AS_OF = "1900000000"


def sha256_of(path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_report(*, roots, out_dir, name, top=None, extra=()):
    json_path = out_dir / f"{name}.json"
    markdown_path = out_dir / f"{name}.md"
    code = report(
        roots=[str(item) for item in roots],
        files=(),
        inventory_path=None,
        as_of=_parse(AS_OF),
        policy=_policy(),
        json_path=str(json_path),
        markdown_path=str(markdown_path),
        baseline=None,
        fail_on=None,
        top=top,
        redact=True,
        source="none",
    )
    return code, json_path, markdown_path


def _policy():
    from certledger.policy.loader import load_policy

    return load_policy()


def _parse(raw: str):
    from certledger.timebase import parse_as_of

    return parse_as_of(raw)


@pytest.fixture
def tree(issue_certificate, tmp_path):
    """A small tree: two certificates inside the expiry window, one well clear.

    Two, not one, because ``--top`` is only observable when there is something to
    trim — and three would trip ``EXPIRY_CLIFF``, which is a different test.
    """
    root = tmp_path / "pki"
    issue_certificate(
        root,
        name="dated",
        cn="dated.example",
        serial=0x51,
        not_valid_after=dt.datetime(2030, 4, 1, tzinfo=dt.timezone.utc),
        write_key=True,
    )
    issue_certificate(
        root,
        name="nearly",
        cn="nearly.example",
        serial=0x53,
        not_valid_after=dt.datetime(2030, 4, 5, tzinfo=dt.timezone.utc),
    )
    issue_certificate(root, name="later", cn="later.example", serial=0x52)
    return root


def test_two_runs_are_byte_identical_in_both_formats(tree, tmp_path) -> None:
    first_code, first_json, first_md = run_report(roots=[tree], out_dir=tmp_path, name="a")
    second_code, second_json, second_md = run_report(roots=[tree], out_dir=tmp_path, name="b")

    assert first_code == second_code
    assert sha256_of(first_json) == sha256_of(second_json)
    assert sha256_of(first_md) == sha256_of(second_md)
    assert first_json.read_bytes().decode("utf-8") != "", "报告空得可疑——判据可能是空跑"


def test_two_separate_processes_produce_the_same_bytes(tree, tmp_path) -> None:
    """The determinism contract is about two *invocations*, not one interpreter.

    Two calls in one process share a hash seed and a warm interpreter, so a
    rendering that depended on ``set``/``dict`` iteration order — or on anything
    else that is random per process — would still look deterministic here. Running
    the console entry point twice makes the comparison the real one: different
    process, different hash seed, same bytes.

    Both formats are compared, and the two documents are compared to each other's
    previous run rather than to a stored expectation, because a stored expectation
    is exactly the thing that would have to be regenerated after the defect.
    """
    import os
    import subprocess
    import sys

    repo = Path(__file__).resolve().parent.parent
    env = {
        **os.environ,
        "PYTHONPATH": str(repo / "src"),
        "PYTHONUTF8": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    produced = []
    for index in (1, 2):
        json_path = tmp_path / f"proc{index}.json"
        markdown_path = tmp_path / f"proc{index}.md"
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "certledger",
                "report",
                "--roots",
                str(tree),
                "--source",
                "none",
                "--as-of",
                AS_OF,
                "--json",
                str(json_path),
                "--markdown",
                str(markdown_path),
            ],
            capture_output=True,
            env=env,
            cwd=str(repo),
            timeout=300,
        )
        assert completed.returncode in (0, 1), completed.stderr.decode("utf-8", "replace")
        produced.append((json_path, markdown_path))

    assert sha256_of(produced[0][0]) == sha256_of(produced[1][0]), "JSON 跨进程不一致"
    assert sha256_of(produced[0][1]) == sha256_of(produced[1][1]), "Markdown 跨进程不一致"
    assert len(produced[0][0].read_bytes()) > 500, "文档小得可疑——判据可能是空跑"


def test_key_order_is_declared_in_the_report(tree, tmp_path) -> None:
    _, json_path, _ = run_report(roots=[tree], out_dir=tmp_path, name="order")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert list(payload) == [
        "schema_version",
        "kind",
        "tool_version",
        "as_of",
        "as_of_utc",
        "policy_version",
        "policy_sha256",
        "fail_on",
        "exit_code",
        "summary",
        "certificates",
        "findings",
        "expiries",
    ]
    if payload["findings"]:
        assert list(payload["findings"][0]) == [
            "code",
            "severity",
            "subject",
            "fingerprint",
            "evidence",
            "rule_source",
        ]


def test_findings_are_sorted_by_severity_then_code_then_subject(issue_certificate, tmp_path) -> None:
    """One order for both formats (``data/README`` §五.9)."""
    from certledger.model import SEVERITY_ORDER

    root = tmp_path / "ordered"
    issue_certificate(
        root,
        name="expired-a",
        cn="a.example",
        serial=0x61,
        not_valid_after=dt.datetime(2020, 2, 1, tzinfo=dt.timezone.utc),
        write_key=True,
    )
    issue_certificate(
        root,
        name="expired-b",
        cn="b.example",
        serial=0x62,
        not_valid_after=dt.datetime(2020, 3, 1, tzinfo=dt.timezone.utc),
        write_key=True,
    )
    _, json_path, _ = run_report(roots=[root], out_dir=tmp_path, name="sorted")
    findings = json.loads(json_path.read_text(encoding="utf-8"))["findings"]
    assert {item["code"] for item in findings} == {"EXPIRED", "PRIVATE_KEY_UNENCRYPTED"}
    keys = [
        (SEVERITY_ORDER[item["severity"]], item["code"], item["subject"], item["fingerprint"])
        for item in findings
    ]
    assert keys == sorted(keys)
    # The subject order is the point: two findings of equal severity and code are
    # separated by their subject, not by the order the two files were walked. The
    # key-side findings carry no subject (a private key has none), so they sort
    # after both certificate-side ones.
    assert [item["subject"] for item in findings] == [
        "CN=a.example",
        "CN=b.example",
        "",
        "",
    ]


def test_the_report_does_not_depend_on_the_order_of_the_roots(issue_certificate, tmp_path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    issue_certificate(left, name="one", cn="one.example", serial=0x71)
    issue_certificate(right, name="two", cn="two.example", serial=0x72)

    _, forward_json, forward_md = run_report(roots=[left, right], out_dir=tmp_path, name="forward")
    _, backward_json, backward_md = run_report(roots=[right, left], out_dir=tmp_path, name="backward")

    assert sha256_of(forward_json) == sha256_of(backward_json)
    assert sha256_of(forward_md) == sha256_of(backward_md)
    payload = json.loads(forward_json.read_text(encoding="utf-8"))
    assert len(payload["certificates"]) == 2


def test_top_trims_the_expiry_table_only(tree, tmp_path) -> None:
    """``--top`` is presentation (``plan/03`` §③ 过期表).

    The two halves of the rule are checked together on purpose: a change that
    trimmed the findings list and a change that made ``--top`` shrink the exit
    code both fail here, and a report whose gate depends on how much of it you
    chose to print is a gate that a flag can open.
    """
    full_code, full_json, full_md = run_report(roots=[tree], out_dir=tmp_path, name="full")
    top_code, top_json, top_md = run_report(roots=[tree], out_dir=tmp_path, name="top", top=1)

    full = json.loads(full_json.read_text(encoding="utf-8"))
    trimmed = json.loads(top_json.read_text(encoding="utf-8"))

    assert full["findings"] == trimmed["findings"], "--top 不得裁剪 finding 全集"
    assert full["certificates"] == trimmed["certificates"]
    assert full_code == top_code
    assert full["exit_code"] == trimmed["exit_code"]
    assert trimmed["summary"]["expiries_total"] == full["summary"]["expiries_total"]
    assert trimmed["summary"]["expiries_shown"] == 1
    assert len(trimmed["expiries"]) == 1
    assert len(full["expiries"]) == full["summary"]["expiries_total"]
    assert full_md.read_bytes() != top_md.read_bytes(), "裁剪必须真的影响展示"


def test_markdown_has_one_row_per_finding(tree, tmp_path) -> None:
    """The two formats are one model, so the table cannot disagree (渲染三律 3)."""
    _, json_path, markdown_path = run_report(roots=[tree], out_dir=tmp_path, name="rows")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    markdown = markdown_path.read_text(encoding="utf-8")

    section = markdown.split("## Findings", 1)[1]
    section = section.split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    assert len(rows) == len(payload["findings"]) + 2, "表格 = 表头 + 分隔行 + 每条 finding 一行"


def test_markdown_carries_no_external_link(tree, tmp_path) -> None:
    """Zero outbound references (渲染三律 2): citations are text, not links."""
    _, _, markdown_path = run_report(roots=[tree], out_dir=tmp_path, name="links")
    text = markdown_path.read_text(encoding="utf-8")
    assert "http://" not in text
    assert "https://" not in text
    assert "]" + "(" not in text, "报告里出现了 Markdown 链接语法"


def test_a_url_inside_a_certificate_name_is_defused_not_a_link(
    issue_certificate, tmp_path
) -> None:
    """A URL in a certificate *name* is data, not a link the report introduced.

    Real trust stores hold such names — the ``USERTrust`` root's subject reads
    ``CN=http://www.usertrust.com`` — so a report over a machine is guaranteed to
    carry one. The value must still render (the body stays free of any
    ``http(s)://`` substring, and of link syntax), which is what 渲染三律 2 is
    about; before the defusing, ``report --markdown`` raised and quit with a
    traceback the moment such a certificate reached a finding.
    """
    root = tmp_path / "pki"
    issue_certificate(root, name="usertrust-like", cn="http://www.usertrust.com", serial=0x63)
    code, _, markdown_path = run_report(roots=[root], out_dir=tmp_path, name="urlnamed")
    text = markdown_path.read_text(encoding="utf-8")
    assert code == 0
    assert "http://" not in text
    assert "https://" not in text
    assert "]" + "(" not in text, "报告里出现了 Markdown 链接语法"
    assert "http\\://www.usertrust.com" in text, "URL 应被转义保留，而不是整条丢掉"


def test_neither_format_carries_a_timestamp_host_or_user(tree, tmp_path) -> None:
    """D9: the report must be publishable as it stands."""
    _, json_path, markdown_path = run_report(roots=[tree], out_dir=tmp_path, name="private")
    for text in (
        json_path.read_text(encoding="utf-8"),
        markdown_path.read_text(encoding="utf-8"),
    ):
        # ``as_of`` is a date and is meant to be there; a *run* timestamp is not.
        for forbidden in ("scanned_at", "parsed_at", "generated_at", "hostname", "username", "host"):
            assert forbidden not in text, forbidden
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["as_of"] == AS_OF


def test_absolute_paths_are_masked_in_both_formats(tmp_path) -> None:
    """A diagnostic finding keeps its file name and loses its machine prefix.

    Both formats are checked: masking is applied to the finished document, so a
    format that rendered from a *different* copy of it would be the one place the
    mask could go missing.
    """
    from certledger.render.redact import MASK

    noisy = tmp_path / "noisy"
    noisy.mkdir()
    (noisy / "notes.bin").write_bytes(b"\x00\x01\x02 binary, not a certificate\n")
    _, json_path, markdown_path = run_report(roots=[noisy], out_dir=tmp_path, name="mask")

    json_text = json_path.read_text(encoding="utf-8")
    markdown_text = markdown_path.read_text(encoding="utf-8")
    assert MASK in json_text and MASK in markdown_text, "绝对路径没有被打码"
    for text in (json_text, markdown_text):
        assert str(tmp_path) not in text, "报告的绝对路径前缀泄漏了"
        # The basename survives, which is what keeps the finding actionable.
        assert "notes.bin" in text
