"""Architecture gates expressed as tests.

These are the invariants that a code review cannot reliably hold (plan/02 §七).
Each one is written to fail when the behaviour is broken, and each has a
mutation recorded in ``plan/05`` §DoD so the gate itself is falsifiable.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from certledger import __version__

SRC = Path(__file__).resolve().parent.parent / "src" / "certledger"


def module_files() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def imports_of(path: Path) -> set[str]:
    """Collect every imported module name, including relative and from-imports.

    ``from .. import X`` gives ``module is None`` with the name in ``names``;
    ``from pkg import sub`` puts the submodule in ``names`` too. Both must be
    considered or the gate silently misses those forms.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    package = _package_of(path)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(package, node)
            if base:
                found.add(base)
            for alias in node.names:
                found.add(f"{base}.{alias.name}" if base else alias.name)
    return found


def _package_of(path: Path) -> str:
    relative = path.relative_to(SRC.parent).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _resolve_relative(package: str, node: ast.ImportFrom) -> str:
    if not node.level:
        return node.module or ""
    parts = package.split(".")
    # level 1 = current package, level 2 = parent, ...
    keep = len(parts) - (node.level - 1)
    base_parts = parts[: max(keep, 0)]
    if node.module:
        base_parts += node.module.split(".")
    return ".".join(base_parts)


def test_no_network_imports_anywhere() -> None:
    """Offline by design: no module may import a networking library (plan/02 §七)."""
    forbidden_prefixes = (
        "socket",
        "ssl",
        "http",
        "urllib",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "smtplib",
        "telnetlib",
    )
    offenders: list[str] = []
    files = module_files()
    assert len(files) >= 8, f"only scanned {len(files)} modules — the gate is vacuous"
    for path in files:
        for name in imports_of(path):
            root = name.split(".")[0]
            if root in forbidden_prefixes:
                offenders.append(f"{path.relative_to(SRC.parent.parent)}: {name}")
    assert offenders == [], offenders


def test_single_clock_source() -> None:
    """Only ``timebase.py`` may touch the wall clock (K2)."""
    offenders: list[str] = []
    pattern = re.compile(r"\b(datetime\.now|datetime\.utcnow|time\.time|time\.localtime)\s*\(")
    files = module_files()
    assert len(files) >= 8, f"only scanned {len(files)} modules — the gate is vacuous"
    for path in files:
        if path.name == "timebase.py":
            continue
        if pattern.search(path.read_text(encoding="utf-8")):
            offenders.append(str(path.relative_to(SRC.parent.parent)))
    assert offenders == [], offenders


def test_render_layer_does_not_judge() -> None:
    """Rendering must not import the rule engine (plan/03 §④ 渲染层零判定)."""
    render_dir = SRC / "render"
    for path in render_dir.rglob("*.py"):
        names = imports_of(path)
        assert not any(name.startswith("certledger.hygiene") for name in names), (
            f"{path.name} imports the rule engine; rendering must stay judgement-free"
        )


def test_version_has_one_source() -> None:
    """``pyproject.toml`` must not repeat the version literal (plan/02 §四)."""
    pyproject = (SRC.parent.parent / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in pyproject
    assert not re.search(r'^version\s*=\s*"', pyproject, re.MULTILINE)
    assert __version__


def test_installed_metadata_matches_module() -> None:
    """Catches the classic "edited __init__, forgot the build" drift."""
    from importlib.metadata import PackageNotFoundError, version

    try:
        installed = version("certledger")
    except PackageNotFoundError:
        pytest.skip("certledger is not installed in this interpreter")
    assert installed == __version__


def test_shells_raise_instead_of_returning_empty() -> None:
    """An empty result is a confident wrong answer (plan/06 R8)."""
    from certledger import collectors, containers, hygiene, inventory, render

    with pytest.raises(NotImplementedError):
        collectors.collect(
            roots=[], files=[], source="none", follow_symlinks=False, max_size=None, policy=None
        )
    with pytest.raises(NotImplementedError):
        inventory.build(roots=[], files=[], source="none", follow_symlinks=False, policy=None)
    with pytest.raises(NotImplementedError):
        hygiene.evaluate(
            roots=[], files=[], inventory_path=None, as_of=None, policy=None, source="none"
        )
    with pytest.raises(NotImplementedError):
        containers.inspect(paths=[], show_aliases=False, password_env=None, policy=None, json_path=None)
    with pytest.raises(NotImplementedError):
        render.render(
            roots=[],
            files=[],
            inventory_path=None,
            as_of=None,
            policy=None,
            json_path=None,
            markdown_path=None,
            baseline=None,
            fail_on=None,
            top=None,
            redact=True,
            source="none",
        )


def test_cli_help_has_no_internal_milestone_references() -> None:
    """User-facing text must not cite internal plan numbers (plan/06 R7)."""
    from certledger.cli import build_parser

    text = build_parser().format_help()
    assert not re.search(r"\bM[0-9]\b", text), text
