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


def test_no_module_still_refuses_to_answer() -> None:
    """The shell era is over: nothing raises ``NotImplementedError`` any more.

    The rule this replaces was "a shell never answers with an empty document"
    (plan/06 R8). Every stage has since landed, so the rule is now asserted in
    the form it took on: no ``raise NotImplementedError`` survives anywhere in
    the package. ``cli.main`` still *catches* it — that is a net under a future
    stage added to the surface before it is implemented — so the check is on the
    ``raise`` statement, not on the name.
    """
    offenders: list[str] = []
    files = module_files()
    assert len(files) >= 8, f"only scanned {len(files)} modules — the gate is vacuous"
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise):
                continue
            target = node.exc
            name = getattr(target, "id", None) or getattr(getattr(target, "func", None), "id", None)
            if name == "NotImplementedError":
                offenders.append(f"{path.relative_to(SRC.parent.parent)}:{node.lineno}")
    assert offenders == [], offenders


def test_every_stage_answers_instead_of_raising(tmp_path) -> None:
    """The positive half of the retired shell rule, for every stage at once.

    Each entry point must return a *document*, over an empty tree, rather than an
    exception or ``None``. "Nothing here" is an answer about the tree, and it is
    only trustworthy because it comes with counters proving the tree was walked.
    """
    from certledger.containers import read_container
    from certledger.inventory import build
    from certledger.policy.loader import load_policy
    from certledger.render import render

    policy = load_policy()

    # containers: a path that is not a container yields a record, not a raise.
    plain = tmp_path / "notes.txt"
    plain.write_text("not a container\n", encoding="utf-8")
    reading = read_container(str(plain))
    assert reading.unreadable, reading
    assert reading.format == "unknown"

    # render: handed a findings document, it renders and returns an exit code.
    ledger = build(roots=[str(tmp_path)], files=[], source="none", follow_symlinks=False, policy=policy)
    exit_code = render(
        findings_document={
            "kind": "hygiene",
            "as_of": "1900000000",
            "as_of_utc": "2030-03-17T17:46:40Z",
            "policy_version": policy.version,
            "policy_sha256": policy.sha256,
            "findings": [],
            "summary": {
                "records": {"certs": 0, "keys": 0, "diagnostics": 0},
                "findings": 0,
                "by_severity": {"ERROR": 0, "WARN": 0, "INFO": 0},
                "suppressed": 0,
                "suppressed_by_code": {},
            },
        },
        ledger=ledger,
        policy=policy,
        fail_on=None,
        top=None,
        redact=True,
        json_path=str(tmp_path / "report.json"),
        markdown_path=str(tmp_path / "report.md"),
        baseline=None,
    )
    assert exit_code == 0
    assert (tmp_path / "report.json").is_file()
    assert (tmp_path / "report.md").is_file()


def test_collector_returns_counts_instead_of_raising(tmp_path) -> None:
    """The positive half of the shell rule, for the module that has landed."""
    from certledger.collectors import collect
    from certledger.policy.loader import load_policy

    payload = collect(
        roots=[str(tmp_path)],
        files=[],
        source="none",
        follow_symlinks=False,
        max_size=None,
        policy=load_policy(),
    )
    assert payload["kind"] == "collect"
    assert payload["candidates"] == []
    summary = payload["summary"]
    for counter in ("visited", "scanned", "skipped", "directories"):
        assert counter in summary, counter
    assert summary["visited"] == summary["scanned"] + summary["skipped"]


def test_inventory_returns_a_ledger_instead_of_raising(tmp_path) -> None:
    """The positive half of the shell rule, for the second module that landed.

    An empty tree must produce an *empty ledger with counters*, not an exception
    and not ``None``: "0 certificates, 0 files visited" is a statement about the
    tree, and it is only trustworthy because the walk counters prove the walk
    happened.
    """
    from certledger.inventory import build
    from certledger.policy.loader import load_policy

    payload = build(
        roots=[str(tmp_path)],
        files=[],
        source="none",
        follow_symlinks=False,
        policy=load_policy(),
    )
    assert payload["kind"] == "inventory"
    assert payload["certs"] == []
    assert payload["keys"] == []
    assert payload["diagnostics"] == []
    for key in ("certs", "keys", "cert_sources", "key_sources", "paired_keys", "collect"):
        assert key in payload["summary"], key
    assert payload["summary"]["collect"]["visited"] == 0


def test_hygiene_returns_findings_instead_of_raising(tmp_path) -> None:
    """The positive half of the shell rule, for the third module that landed.

    An empty tree must produce a *findings document with counters*, not an
    exception and not ``None``. The document also echoes the instant it was
    judged against, because a report with no ``--as-of`` cannot be reproduced —
    the whole reason the flag is mandatory.
    """
    from certledger.hygiene import evaluate
    from certledger.policy.loader import load_policy
    from certledger.timebase import parse_as_of

    payload = evaluate(
        roots=[str(tmp_path)],
        files=[],
        inventory_path=None,
        as_of=parse_as_of("1900000000"),
        policy=load_policy(),
        source="none",
    )
    assert payload["kind"] == "hygiene"
    assert payload["findings"] == []
    assert payload["as_of"] == "1900000000"
    assert payload["as_of_utc"] == "2030-03-17T17:46:40Z"
    assert payload["summary"]["findings"] == 0
    assert payload["summary"]["records"]["certs"] == 0


def test_collectors_import_no_network_modules() -> None:
    """Module-scoped version of the global gate, pinned to the collector (R9).
    The global check would still pass if the collector grew a helper in another
    package that imported ``socket``. This one asserts the property where it
    matters most: the module that touches the filesystem and subprocesses is
    also the one most likely to grow a "fetch the CRL" shortcut.
    """
    collectors = SRC / "collectors"
    files = sorted(collectors.rglob("*.py"))
    assert files, "collectors 目录里没有模块——判据是空的"
    forbidden = (
        "socket", "ssl", "http", "urllib", "requests", "httpx", "aiohttp",
        "ftplib", "smtplib", "telnetlib", "xmlrpc", "asyncio",
    )
    offenders: list[str] = []
    for path in files:
        for name in imports_of(path):
            if name.split(".")[0] in forbidden:
                offenders.append(f"{path.name}: {name}")
    assert offenders == [], offenders


def test_only_parsing_computes_hashes() -> None:
    """K1: one hashing entry point for **key material**. A second one drifts.

    ``policy/loader.py`` is exempt and named explicitly rather than by a loose
    pattern: it hashes the policy *document* (``policy_sha256``, so a report can
    say which rules produced it), which is a different object from a
    certificate. Anything else importing ``hashlib`` is a second fingerprint
    path and fails here.
    """
    allowed = {
        SRC / "parsing" / "fingerprint.py",
        SRC / "policy" / "loader.py",
    }
    offenders: list[str] = []
    for path in module_files():
        if path in allowed:
            continue
        if "hashlib" in path.read_text(encoding="utf-8"):
            offenders.append(str(path.relative_to(SRC.parent.parent)))
    assert offenders == [], offenders


def test_cli_help_has_no_internal_milestone_references() -> None:
    """User-facing text must not cite internal plan numbers (plan/06 R7)."""
    from certledger.cli import build_parser

    text = build_parser().format_help()
    assert not re.search(r"\bM[0-9]\b", text), text
