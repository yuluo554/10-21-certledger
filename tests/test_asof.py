"""``--as-of`` is the only notion of "now" — and the ledger does not move with it.

The distinguishing claim of this project is that a verdict is a function of
``(ledger, policy, instant)`` and of nothing else. This file tests the third
argument: one machine, one ledger, two instants, two conclusions. A test that
only checked "an expired certificate is reported" would pass for an
implementation that read the wall clock and happened to agree today.

The other half is the negative one: changing ``--as-of`` must not change the
*inventory*. If the record count moved when the instant moved, the ledger would
be a function of the report and a diff of two runs would be meaningless.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from certledger.errors import CliError
from certledger.hygiene import evaluate
from certledger.policy.loader import load_policy
from certledger.timebase import parse_as_of, parse_stamp

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "fixtures" / "out"
AS_OF = 1_900_000_000  # 2030-03-17T17:46:40Z, the sample baseline
EARLIER = 1_700_000_000  # 2023-11-14T22:13:20Z, five years before the samples exist

_HAVE_ARTIFACTS = pytest.mark.skipif(
    not OUT.is_dir(), reason="fixtures/out 不存在：样本按需生成，不入库"
)


def run(case: str, instant: int) -> dict:
    files = [str(OUT / name) for name in sorted(
        str(path.relative_to(OUT)).replace("\\", "/")
        for path in (OUT / case).iterdir()
        if path.is_file()
    )]
    return evaluate(
        roots=[],
        files=files,
        inventory_path=None,
        as_of=parse_as_of(str(instant)),
        policy=load_policy(),
        source="none",
    )


def codes(payload: dict) -> set[str]:
    return {item["code"] for item in payload["findings"]}


# ── the verdict moves with the instant ─────────────────────────────────────


@_HAVE_ARTIFACTS
def test_the_same_fixture_reaches_a_different_verdict_at_a_different_instant() -> None:
    """One machine, two instants, two conclusions (``plan/06`` §1.1).

    ``expiring/`` expires on 2030-03-27. Judged at the baseline instant it is
    inside the warn window; judged five years earlier it is comfortably valid.
    Nothing about the files changed between the two calls.
    """
    now = run("expiring", AS_OF)
    then = run("expiring", EARLIER)

    assert "EXPIRING" in codes(now)
    assert "EXPIRING" not in codes(then)
    assert "EXPIRED" not in codes(then)
    assert codes(now) != codes(then)


@_HAVE_ARTIFACTS
def test_the_verdict_walks_expiring_then_expired() -> None:
    """The three states are monotone along the time axis, and the boundary is one second wide.

    Same certificate, three instants: comfortably valid → ``EXPIRING`` →
    ``EXPIRED``. If the rule were "expires within 30 days" without a direction,
    the middle and last could not be told apart.
    """
    entry = json.loads((ROOT / "fixtures" / "expected.json").read_text(encoding="utf-8"))
    case = next(item for item in entry["cases"] if item["case"] == "expiring")
    not_after = next(
        parse_stamp(artifact["not_after"])
        for artifact in case["artifacts"]
        if artifact["kind"] == "cert"
    )

    before = codes(run("expiring", not_after - 400 * 86400))
    assert "EXPIRING" not in before and "EXPIRED" not in before

    asserting = codes(run("expiring", not_after - 10 * 86400))
    assert "EXPIRING" in asserting and "EXPIRED" not in asserting

    after = codes(run("expiring", not_after + 1))
    assert "EXPIRED" in after and "EXPIRING" not in after


@_HAVE_ARTIFACTS
def test_the_ledger_does_not_move_when_the_instant_does() -> None:
    """The records are the machine; only the judgement is the instant.

    If the record count changed with ``--as-of``, the ledger would be a function
    of the report — and two runs could not be diffed.
    """
    now = run("expiring", AS_OF)
    then = run("expiring", EARLIER)
    assert now["summary"]["records"] == then["summary"]["records"]
    assert now["summary"]["records"]["certs"] == 1
    assert now["summary"]["records"]["keys"] == 1


@_HAVE_ARTIFACTS
def test_the_document_echoes_the_instant_it_was_judged_at() -> None:
    for instant in (AS_OF, EARLIER):
        payload = run("expiring", instant)
        assert payload["as_of"] == str(instant)
        assert payload["as_of_utc"] == parse_as_of(str(instant)).iso


# ── it is not optional ─────────────────────────────────────────────────────


def test_missing_as_of_is_refused_at_the_engine_too(tmp_path) -> None:
    """Not only at the parser: the engine has no fallback either (K2).

    A CLI-only guard would leave a second door open for any caller that builds
    the arguments itself.
    """
    with pytest.raises(CliError) as error:
        evaluate(
            roots=[], files=[], inventory_path=None,
            as_of=None, policy=load_policy(), source="none",
        )
    assert "as-of" in str(error.value)


def test_missing_as_of_is_usage_error_at_the_cli() -> None:
    """And the documented exit code for it is 2 (``data/README`` §五.8)."""
    import io
    import sys

    from certledger.cli import main
    from certledger.errors import EXIT_USAGE

    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(["hygiene", "--roots", "."])
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    assert code == EXIT_USAGE
    assert "--as-of" in err.getvalue()


def test_a_naive_timestamp_is_refused() -> None:
    """An offset-free ISO stamp would make the verdict depend on the host zone."""
    with pytest.raises(CliError):
        parse_as_of("2030-03-17T17:46:40")