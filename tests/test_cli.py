"""CLI surface: argument parsing, help, exit codes.

M0 asserts the *surface* is complete and honest. It does not assert that the
analysis produces anything — the modules are shells on purpose (plan/03 §M0).
"""

from __future__ import annotations

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


def test_unimplemented_module_exits_two_without_claiming_success() -> None:
    code, out, err = run_cli("collect", "--roots", ".")
    assert code == EXIT_USAGE
    assert out == ""  # no fabricated empty result on stdout
    assert "尚未" in err


def test_unimplemented_message_cites_no_internal_milestone() -> None:
    """User-facing text must not reference internal plan numbers (plan/06 R7)."""
    code, _, err = run_cli("collect", "--roots", ".")
    assert code == EXIT_USAGE
    assert "M1" not in err and "M2" not in err and "M3" not in err


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
