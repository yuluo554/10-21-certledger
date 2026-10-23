"""Documentation promises that a reader can check mechanically.

The first screen of the README is the whole positioning argument (plan/00 D1):
if it stops naming the two competitors and the scope difference, the project
reads as another expiry checker.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def first_screen() -> str:
    """Everything before the first horizontal rule — the part a visitor sees."""
    text = README.read_text(encoding="utf-8")
    return text.split("\n---\n", 1)[0]


def test_first_screen_names_the_scope_difference() -> None:
    screen = first_screen()
    assert "ChainWarden" in screen
    assert "one PEM file" in screen
    assert "one machine" in screen


def test_first_screen_names_the_three_extra_input_surfaces() -> None:
    screen = first_screen()
    for word in ("containers", "trust store", "private key"):
        assert word in screen, word


def test_privacy_statement_is_on_the_first_screen() -> None:
    screen = first_screen()
    for phrase in ("zero network", "zero telemetry", "never enter this repository"):
        assert phrase in screen, phrase


def test_status_line_carries_version_and_capability_only() -> None:
    """Release state belongs to the Release page, not the packaged README (skill §C).

    The version is read from the package's single source (``certledger.__version__``)
    rather than pinned as a literal: the README status line is required to carry
    whatever version ships, so a literal here would go stale on every release and
    the assertion would have to be edited to keep up — a drift the test itself
    should not introduce (``plan/05`` §三「版本号唯一来源」).
    """
    from certledger import __version__

    screen = first_screen()
    line = next((ln for ln in screen.split("\n") if ln.startswith("`Status:")), None)
    assert line is not None, "README must keep a Status line on the first screen"
    assert f"v{__version__}" in line
    assert "published" not in line.lower()
    assert "release" not in line.lower()


def test_no_first_or_unique_claims() -> None:
    """plan/01 §1.4: the open-source-gap argument is soft and must not be overstated."""
    text = README.read_text(encoding="utf-8")
    for word in ("first tool", "the only", "the first", "首创", "唯一"):
        assert word not in text, word


def test_readme_commands_match_the_parser() -> None:
    """Reflection check: every documented subcommand must exist (skill §A ④)."""
    from certledger.cli import build_parser

    available = set(build_parser()._subparsers._group_actions[0].choices)  # type: ignore[attr-defined]
    documented = set(re.findall(r"^certledger (\w+)", README.read_text(encoding="utf-8"), re.M))
    assert documented, "no certledger commands found in README"
    assert documented <= available, documented - available


def test_readme_states_the_three_exit_codes() -> None:
    text = README.read_text(encoding="utf-8")
    for code in ("`0`", "`1`", "`2`"):
        assert code in text, code


def test_no_sibling_project_domains_mentioned() -> None:
    """Brand isolation (plan/00 D12): nothing from the sibling series appears."""
    text = README.read_text(encoding="utf-8")
    assert "sister project" not in text.lower()
