"""The exit-code contract: 0, 1, 2 — and nothing else (``data/README`` §五.8).

Three codes, three meanings, and one trap: a gate that a flag can quietly open.

* ``0`` — nothing reached the ``--fail-on`` threshold;
* ``1`` — something did; produced by ``report`` and by nothing else;
* ``2`` — the input, the policy or an argument is wrong (raised as ``CliError``,
  turned into a process code only by ``cli.main``).

``--fail-on none`` returns 0 *and still prints every finding* — "do not fail my
build" and "do not tell me what you found" are different requests.

The certificates are built here, so these assertions run in CI (which generates
no fixtures), and each case differs from its neighbour by exactly one fact: a
validity date, a severity, or a flag.
"""

from __future__ import annotations

import datetime as dt

import pytest

from certledger.cli import main
from certledger.errors import EXIT_OK, EXIT_THRESHOLD, EXIT_USAGE

AS_OF = "1900000000"
NOW = dt.datetime(2030, 3, 17, tzinfo=dt.timezone.utc)


def run_cli(*argv: str) -> tuple[int, str, str]:
    import io
    import sys

    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(list(argv))
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


@pytest.fixture
def valid_tree(issue_certificate, tmp_path):
    """A certificate that fires no severity at or above WARN."""
    root = tmp_path / "valid"
    issue_certificate(
        root,
        name="fine",
        cn="fine.example",
        serial=0x81,
        not_valid_before=dt.datetime(2029, 1, 1, tzinfo=dt.timezone.utc),
        not_valid_after=dt.datetime(2031, 1, 1, tzinfo=dt.timezone.utc),
    )
    return root


@pytest.fixture
def expired_tree(issue_certificate, tmp_path):
    """A certificate that is already expired at ``AS_OF`` (an ERROR finding)."""
    root = tmp_path / "expired"
    issue_certificate(
        root,
        name="gone",
        cn="gone.example",
        serial=0x82,
        not_valid_before=dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc),
        not_valid_after=dt.datetime(2029, 1, 1, tzinfo=dt.timezone.utc),
    )
    return root


def test_zero_when_nothing_reaches_the_threshold(valid_tree) -> None:
    code, out, err = run_cli("report", "--roots", str(valid_tree), "--source", "none", "--as-of", AS_OF)
    assert code == EXIT_OK, err
    import json

    payload = json.loads(out)
    assert payload["exit_code"] == 0
    assert payload["fail_on"] == "ERROR"
    assert {item["severity"] for item in payload["findings"]} <= {"INFO"}


def test_one_when_a_finding_reaches_the_threshold(expired_tree) -> None:
    code, out, _ = run_cli("report", "--roots", str(expired_tree), "--source", "none", "--as-of", AS_OF)
    assert code == EXIT_THRESHOLD
    import json

    payload = json.loads(out)
    assert payload["exit_code"] == 1
    assert any(item["code"] == "EXPIRED" for item in payload["findings"])


def test_fail_on_none_is_always_zero_but_still_reports(expired_tree) -> None:
    """The gate is off; the findings are not."""
    code, out, _ = run_cli(
        "report", "--roots", str(expired_tree), "--source", "none", "--as-of", AS_OF,
        "--fail-on", "none",
    )
    assert code == EXIT_OK
    import json

    payload = json.loads(out)
    assert payload["fail_on"] == "none"
    assert payload["exit_code"] == 0
    assert any(item["code"] == "EXPIRED" for item in payload["findings"]), (
        "--fail-on none 关掉的是门禁，不是报告"
    )


def test_lowering_the_threshold_turns_a_pass_into_a_failure(valid_tree) -> None:
    """Same input, same instant, different threshold, different verdict.

    This is the pair that pins the threshold's meaning: an ``INFO`` finding passes
    under the policy default and fails when the caller asks to be stopped at
    ``INFO``.
    """
    default_code, out, _ = run_cli(
        "report", "--roots", str(valid_tree), "--source", "none", "--as-of", AS_OF
    )
    strict_code, strict_out, _ = run_cli(
        "report", "--roots", str(valid_tree), "--source", "none", "--as-of", AS_OF,
        "--fail-on", "INFO",
    )
    import json

    assert default_code == EXIT_OK
    findings = json.loads(out)["findings"]
    assert findings and {item["severity"] for item in findings} == {"INFO"}
    assert strict_code == EXIT_THRESHOLD
    assert json.loads(strict_out)["findings"] == findings


def test_missing_as_of_is_exit_two(tmp_path) -> None:
    code, _, err = run_cli("report", "--roots", str(tmp_path), "--source", "none")
    assert code == EXIT_USAGE
    assert "--as-of" in err


def test_unreadable_policy_is_exit_two(tmp_path) -> None:
    code, _, err = run_cli(
        "report", "--roots", str(tmp_path), "--source", "none", "--as-of", AS_OF,
        "--policy", str(tmp_path / "missing.json"),
    )
    assert code == EXIT_USAGE
    assert "策略文件" in err


def test_missing_inventory_is_exit_two(tmp_path) -> None:
    """A ``--inventory`` file that is not there is not an empty ledger."""
    code, _, err = run_cli(
        "report", "--inventory", str(tmp_path / "ledger.json"), "--source", "none", "--as-of", AS_OF
    )
    assert code == EXIT_USAGE
    assert "台账文件" in err


def test_an_unwritable_output_path_is_exit_two(valid_tree, tmp_path) -> None:
    """``--json`` pointing into a directory that does not exist is caught, not traced."""
    code, _, err = run_cli(
        "report", "--roots", str(valid_tree), "--source", "none", "--as-of", AS_OF,
        "--json", str(tmp_path / "no-such-dir" / "report.json"),
    )
    assert code == EXIT_USAGE
    assert "输出不可写" in err
    assert "Traceback" not in err


def test_an_unavailable_backend_does_not_change_the_exit_code(valid_tree) -> None:
    """K6 / D11: macOS is never verified here, so it degrades — and does not gate.

    ``SOURCE_UNAVAILABLE`` is an ``INFO`` record. A machine missing a backend is
    not a machine with a problem in its certificates, and conflating the two
    would make the tool unusable on the platform it cannot test.
    """
    code, out, _ = run_cli(
        "report", "--roots", str(valid_tree), "--source", "macos", "--as-of", AS_OF,
        "--fail-on", "WARN",
    )
    assert code == EXIT_OK
    import json

    payload = json.loads(out)
    assert any(item["code"] == "SOURCE_UNAVAILABLE" for item in payload["findings"])
    assert all(item["severity"] == "INFO" for item in payload["findings"])


def test_a_bad_baseline_is_exit_two(valid_tree, tmp_path) -> None:
    broken = tmp_path / "not-a-report.json"
    broken.write_text('{"kind": "inventory"}\n', encoding="utf-8")
    code, _, err = run_cli(
        "report", "--roots", str(valid_tree), "--source", "none", "--as-of", AS_OF,
        "--baseline", str(broken),
    )
    assert code == EXIT_USAGE
    assert "基线文件类型不符" in err
