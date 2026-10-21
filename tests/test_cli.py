"""CLI surface: argument parsing, help, exit codes.

Every subcommand is live, so the assertions here are about the *surface*: which
arguments parse, which inputs are refused before any work happens, and that the
documented exit codes 0/1/2 are the only ones produced.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest

from certledger import __version__
from certledger.cli import build_parser, main
from certledger.errors import EXIT_USAGE


def run_cli(*argv: str) -> tuple[int, str, str]:
    """Invoke ``main`` in-process, capturing stdout/stderr.

    ``argparse`` writes to ``sys.stdout``/``sys.stderr`` directly, so the
    streams are swapped here rather than relying on capsys inside the helper.
    """
    import io

    out, err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        code = main(list(argv))
    finally:
        sys.stdout, sys.stderr = old_out, old_err
    return code, out.getvalue(), err.getvalue()


def test_help_exits_zero() -> None:
    code, out, err = run_cli("--help")
    assert code == 0
    assert "certledger" in out
    for command in ("collect", "inventory", "hygiene", "report", "containers"):
        assert command in out


def test_version_mentions_single_source_version() -> None:
    code, out, _ = run_cli("--version")
    assert code == 0
    assert __version__ in out


def test_no_subcommand_is_usage_error() -> None:
    code, _, err = run_cli()
    assert code == EXIT_USAGE
    assert "usage" in err.lower()


def test_unknown_subcommand_is_usage_error() -> None:
    code, _, err = run_cli("nonsense")
    assert code == EXIT_USAGE
    assert "nonsense" in err or "invalid choice" in err


@pytest.mark.parametrize("command", ["collect", "inventory", "hygiene", "report"])
def test_missing_roots_and_files_is_usage_error(command: str) -> None:
    argv = [command]
    if command in ("hygiene", "report"):
        argv += ["--as-of", "1900000000"]
    code, _, err = run_cli(*argv)
    assert code == EXIT_USAGE
    assert "--roots" in err or "--files" in err


@pytest.mark.parametrize("command", ["hygiene", "report"])
def test_missing_as_of_is_usage_error(command: str) -> None:
    """No wall-clock default: the argument is required by the parser itself."""
    code, _, err = run_cli(command, "--roots", ".")
    assert code == EXIT_USAGE
    assert "--as-of" in err


def test_bad_as_of_is_usage_error() -> None:
    code, _, err = run_cli("report", "--roots", ".", "--as-of", "not-a-time")
    assert code == EXIT_USAGE
    assert "as-of" in err


def test_naive_as_of_is_rejected() -> None:
    """An ISO timestamp without an offset would make results machine-dependent."""
    code, _, err = run_cli("report", "--roots", ".", "--as-of", "2030-03-17T17:46:40")
    assert code == EXIT_USAGE
    assert "时区" in err


@pytest.mark.parametrize("command", ["collect", "inventory", "hygiene", "report"])
def test_no_command_claims_an_unimplemented_capability(command: str, tmp_path) -> None:
    """The "not available in this version" answer has no reachable trigger (K7).

    ``report`` used to be the last analysis shell, so the K7 assertion pointed at
    it. Every stage has landed, so the rule is stated in the form it can still
    take: a subcommand run against real (if empty) input never produces the
    unimplemented-capability sentence and never exits with a code outside the
    documented set. The sentence and its branch stay in ``cli.main`` as a net
    under a stage that is added to the surface before it is implemented.
    """
    argv = [command, "--roots", str(tmp_path), "--source", "none"]
    if command in ("hygiene", "report"):
        argv += ["--as-of", "1900000000"]
    code, out, err = run_cli(*argv)
    assert code in (0, 1, 2), (command, code, err)
    assert "尚未" not in err, err
    assert "Traceback" not in err, err
    assert out != "", "a landed command must answer with a document"


def test_report_answers_with_a_report_document(tmp_path) -> None:
    """The last stage to land answers with its own document kind."""
    code, out, err = run_cli(
        "report", "--roots", str(tmp_path), "--source", "none", "--as-of", "1900000000"
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["kind"] == "report"
    assert payload["as_of"] == "1900000000"
    assert payload["as_of_utc"] == "2030-03-17T17:46:40Z"
    assert payload["findings"] == []
    assert payload["tool_version"] == __version__


def test_hygiene_answers_instead_of_claiming_unimplemented(tmp_path) -> None:
    """The other half of the same rule, for the module that landed this time.

    An empty tree is used on purpose: a text file would legitimately produce a
    ``SKIP_UNKNOWN_FORMAT`` finding, and this test is about "the command
    answers", not about the rule set.
    """
    code, out, err = run_cli(
        "hygiene", "--roots", str(tmp_path), "--source", "none", "--as-of", "1900000000"
    )
    assert code == 0, err
    payload = json.loads(out)
    assert payload["kind"] == "hygiene"
    assert payload["findings"] == []
    assert payload["as_of_utc"] == "2030-03-17T17:46:40Z"


def test_inventory_answers_instead_of_claiming_unimplemented(tmp_path) -> None:
    """The other half of the same rule: the landed module answers, exit 0."""
    (tmp_path / "notes.txt").write_text("not a certificate\n", encoding="utf-8")
    code, out, err = run_cli("inventory", "--roots", str(tmp_path), "--source", "none")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["kind"] == "inventory"
    assert payload["certs"] == []
    assert payload["summary"]["collect"]["visited"] == 1


def test_error_text_cites_no_internal_milestone(tmp_path) -> None:
    """User-facing text must not reference internal plan numbers (plan/06 R7).

    Checked on a real error path (a policy file that is not there) rather than on
    a shell message, because the rule is about every sentence the tool prints,
    not about the one that happened to exist when the rule was written.
    """
    code, _, err = run_cli(
        "report", "--roots", ".", "--as-of", "1900000000", "--policy", str(tmp_path / "nope.json")
    )
    assert code == EXIT_USAGE
    assert "策略文件" in err
    assert not re.search(r"\bM[0-9]\b", err), err


def test_collect_runs_and_reports_counts(tmp_path) -> None:
    """``collect`` has landed: it answers with counts, exit code 0."""
    (tmp_path / "notes.txt").write_text("not a certificate\n", encoding="utf-8")
    code, out, err = run_cli("collect", "--roots", str(tmp_path), "--source", "none")
    assert code == 0, err
    payload = json.loads(out)
    assert payload["kind"] == "collect"
    assert payload["summary"]["visited"] == 1
    assert payload["summary"]["scanned"] == 1


def test_collect_writes_json_to_a_file(tmp_path) -> None:
    target = tmp_path / "out.json"
    code, out, err = run_cli(
        "collect", "--roots", str(tmp_path), "--source", "none", "--json", str(target)
    )
    assert code == 0, err
    assert target.is_file()
    assert json.loads(target.read_text(encoding="utf-8"))["kind"] == "collect"
    assert "wrote" in out


@pytest.mark.parametrize("command", ["hygiene", "report"])
def test_inventory_path_does_not_require_roots(command: str) -> None:
    """Reading a stored ledger is a valid input; it must not demand --roots."""
    code, _, err = run_cli(command, "--inventory", "ledger.json", "--as-of", "1900000000")
    assert code == EXIT_USAGE
    assert "缺少输入" not in err


def test_policy_missing_is_usage_error(tmp_path) -> None:
    code, _, err = run_cli("collect", "--roots", ".", "--policy", str(tmp_path / "nope.json"))
    assert code == EXIT_USAGE
    assert "策略文件" in err


def test_containers_requires_a_path() -> None:
    code, _, err = run_cli("containers")
    assert code == EXIT_USAGE
    assert "PATH" in err or "required" in err


def test_containers_with_a_path_exits_two_without_a_traceback() -> None:
    """Regression: ``--policy`` alone must not demand ``--roots``.

    ``containers`` takes positional paths and its own ``--policy``. An earlier
    validation gate keyed on "does this command have a policy argument" sent it
    into the ``--roots``-required branch, where ``args.roots`` did not exist:
    the command died with an ``AttributeError`` traceback and exit code 1. The
    documented contract is 0/1/2 only, and a traceback is none of them.
    """
    code, out, err = run_cli("containers", "some.p12")
    assert code == EXIT_USAGE, (code, err)
    assert out == ""
    assert "Traceback" not in err
    assert "AttributeError" not in err


def test_parser_accepts_documented_multi_value_forms() -> None:
    """Reflection check: the documented forms parse (plan/05 §三 发布包实测 ①)."""
    parser = build_parser()
    for argv in (
        ["report", "--roots", "a", "--roots", "b", "--as-of", "1900000000"],
        ["report", "--files", "x.pem", "--as-of", "1900000000"],
        ["report", "--roots", "a", "--as-of", "2030-03-17T17:46:40Z", "--fail-on", "WARN"],
        ["report", "--roots", "a", "--as-of", "1900000000", "--top", "5", "--no-redact"],
        ["containers", "a.p12", "b.jks", "--show-aliases"],
    ):
        args = parser.parse_args(argv)
        handler = getattr(args, "handler", None)
        assert handler is not None, argv


def test_module_entry_point_works() -> None:
    """``python -m certledger`` must reach the same main (plan/02 §四).

    ``PYTHONPATH`` is set explicitly because the subprocess does not inherit the
    ``sys.path`` insertion done in ``conftest.py``; relying on an editable
    install would make this test skip-or-fail depending on the machine.
    """
    import os
    from pathlib import Path

    env = dict(os.environ)
    src = str(Path(__file__).resolve().parent.parent / "src")
    env["PYTHONPATH"] = src + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    result = subprocess.run(
        [sys.executable, "-m", "certledger", "--version"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, result.stderr
    assert __version__ in result.stdout
