#!/usr/bin/env python3
"""Mutation self-test for the two methodology gates.

A gate that has never been seen to fail is a decoration. This script copies the
repository into a scratch directory, breaks exactly one thing per case, and
asserts the corresponding gate turns red; then it confirms the untouched copy is
green.

Every mutation asserts that the file really changed (a no-op mutation makes a
broken gate look green — one of the classic false-gate forms).

Usage:  py -3.12 tools/selftest-gates.py
Exit:   0 all mutations behaved / 1 at least one did not.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAYOUT = "tools/check-sprint-layout.py"
DESENS = "tools/check-desensitized.py"

SKIP = {".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", "fixtures"}


def copy_tree(dest: Path) -> None:
    shutil.copytree(
        ROOT,
        dest,
        ignore=shutil.ignore_patterns(*SKIP),
        dirs_exist_ok=True,
    )


@dataclass
class Mutation:
    name: str
    gate: str
    expect: str  # a check id or "CI_STEP"
    apply: "callable"


def replace(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise AssertionError(f"mutation marker not found in {path.name}: {old[:60]!r}")
    before = path.read_bytes()
    path.write_text(text.replace(old, new, 1), encoding="utf-8", newline="\n")
    if path.read_bytes() == before:
        raise AssertionError(f"mutation made no byte change in {path.name}")


def delete(path: Path) -> None:
    if not path.exists():
        raise AssertionError(f"cannot delete missing {path}")
    path.unlink()


def run_gate(work: Path, gate: str) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(work / gate)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
        cwd=str(work),
    )
    return result.returncode, result.stdout + result.stderr


# ── layout mutations (10) ────────────────────────────────────────────────────
def m01(work: Path) -> None:
    """Drop the anchor file."""
    delete(work / "AGENTS.md")


def m02(work: Path) -> None:
    """Flip a completed milestone back to pending in exactly one copy.

    Targets ``plan/00``'s milestone table deliberately: it is *not* the first
    table in that file whose header mentions 状态 (the document index is), so this
    mutation is the one that proves the gate scans every status table rather
    than stopping at the first one.
    """
    replace(
        work / "plan/00-README总览.md",
        "| **M0 骨架** |",
        "| **M0 骨架** | ⬜ |",
    )


def m03(work: Path) -> None:
    """Write a completed milestone back into plan/06's gap column."""
    replace(
        work / "plan/06-交付对标与决策.md",
        "| G3 | CI 实跑（无远端） | M6 首推后回填真实 run id |",
        "| G3 | CI 实跑（无远端） | 待 M0 收尾 |",
    )


def set_milestone_status(work: Path, rel: str, milestone: int, replacement: str) -> None:
    """Flip one milestone's status inside the *status table* of one document.

    Rewriting only the ``⬜`` marker is not enough: these rows also carry prose
    that may mention ⬜ elsewhere, and the gate reads pending markers from the
    whole row. The mutation must therefore produce a row that says "done" to a
    human as well as to the gate.
    """
    import re as _re

    path = work / rel
    lines = path.read_text(encoding="utf-8").split("\n")
    pattern = _re.compile(rf"^\|\s*\*{{0,2}}M{milestone}\b")
    changed = False
    for i, line in enumerate(lines):
        if not pattern.match(line):
            continue
        if "⬜" not in line and "未开始" not in line:
            continue
        lines[i] = line.replace("⬜ 未开始", replacement).replace("⬜", replacement)
        changed = True
        break
    if not changed:
        raise AssertionError(f"no pending M{milestone} row found in {rel}")
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def m04(work: Path) -> None:
    """Mark a milestone completed in every copy while its handoff is absent.

    The handoff file is removed as well; otherwise the gate finds a valid
    seven-section document and stays green, which would make this mutation a
    no-op. (Flipping a milestone also lights up ``LAYOUT.GAPS``, because the gap
    table still lists it — that is correct behaviour, and this case only asserts
    that ``LAYOUT.HANDOFFS`` is among the reported failures.)
    """
    for rel in ("plan/00-README总览.md", "plan/05-里程碑与发布.md", "README.md"):
        set_milestone_status(work, rel, 1, "✅ 已完成")
    delete(work / "plan/HANDOFF-M1.md")


def m05(work: Path) -> None:
    """Remove the binding line from plan/00."""
    text = (work / "plan/00-README总览.md").read_text(encoding="utf-8")
    line = next((ln for ln in text.split("\n") if ln.startswith("> 方法论：")), None)
    if line is None:
        raise AssertionError("binding line not found")
    replace(work / "plan/00-README总览.md", line + "\n", "")


def m06(work: Path) -> None:
    """Delete a plan document (files check), separately from the anchor."""
    delete(work / "plan/02-架构与技术选型.md")


def m07(work: Path) -> None:
    """Remove a required section heading."""
    replace(
        work / "plan/04-数据计划.md",
        "## 四、数值口径",
        "## 四、其他说明",
    )


def m08(work: Path) -> None:
    """Point the docs at a tools script that does not exist."""
    replace(
        work / "plan/06-交付对标与决策.md",
        "## 五、品牌与合规",
        "## 五、品牌与合规\n\n见 `tools/check-release.py`。",
    )


def m09(work: Path) -> None:
    """Leave the promise-evidence ledger with a stale pending marker."""
    replace(
        work / "plan/00-README总览.md",
        "| ⬜ 待 M3 验证 |\n| 过期判定确定性",
        "| ⬜ 待 M0 验证 |\n| 过期判定确定性",
    )


def m10(work: Path) -> None:
    """Remove a gate step from CI (the gate must notice its own wiring)."""
    path = work / ".github/workflows/ci.yml"
    text = path.read_text(encoding="utf-8")
    marker = "tools/check-desensitized.py"
    if marker not in text:
        raise AssertionError("CI gate step not found")
    path.write_text(text.replace(marker, "tools/nonexistent.py", 1), encoding="utf-8")


# ── desensitization mutations (4) ────────────────────────────────────────────
# The injected strings are assembled from parts on purpose: this file must not
# ship a literal that the desensitization gate would flag, otherwise the gate
# needs a permanent exemption for its own self-test — a blind spot that grows.
_INJECT = {
    "drive": "D:" + "/ProgramData" + "/scratch",
    "msys": "/c/" + "Users/alice/" + "pki",
    "user": "AS" + "US",
    "proxy": "127.0.0." + "1:7897",
}


def _append(work: Path, text: str) -> None:
    replace(
        work / "plan/05-里程碑与发布.md",
        "## 五、已知未验证项",
        "## 五、已知未验证项\n\n" + text,
    )


def d01(work: Path) -> None:
    _append(work, f"本机工作目录 {_INJECT['drive']}。")


def d02(work: Path) -> None:
    _append(work, f"路径 {_INJECT['msys']}。")


def d03(work: Path) -> None:
    _append(work, f"账号 {_INJECT['user']}。")


def d04(work: Path) -> None:
    _append(work, f"代理 http://{_INJECT['proxy']}。")


LAYOUT_MUTATIONS = [
    ("M1 drop AGENTS.md", m01, "LAYOUT.FILES"),
    ("M2 flip one milestone in one copy", m02, "LAYOUT.STATUS"),
    ("M3 gap column names a done milestone", m03, "LAYOUT.GAPS"),
    ("M4 completed milestone without handoff", m04, "LAYOUT.HANDOFFS"),
    ("M5 remove binding line", m05, "LAYOUT.BINDING_HEAD"),
    ("M6 delete a plan document", m06, "LAYOUT.FILES"),
    ("M7 remove a required section", m07, "LAYOUT.SECTIONS"),
    ("M8 doc names a missing tool", m08, "LAYOUT.DOC_TOOLS"),
    ("M9 stale ledger row", m09, "LAYOUT.LEDGER"),
    ("M10 CI gate step missing", m10, "LAYOUT.CI_STEP"),
]

DESENS_MUTATIONS = [
    ("V1 drive-letter path", d01),
    ("V2 MSYS user path", d02),
    ("V3 host username", d03),
    ("V4 loopback proxy", d04),
]


def main() -> int:
    failures: list[str] = []
    print("基线：未改动副本必须全绿")
    with tempfile.TemporaryDirectory(prefix="certledger-selftest-") as tmp:
        base = Path(tmp) / "base"
        copy_tree(base)
        code, output = run_gate(base, LAYOUT)
        print(f"  layout   rc={code}")
        if code != 0:
            failures.append("baseline layout gate is not green")
            print(output)
        code, output = run_gate(base, DESENS)
        print(f"  desens   rc={code}")
        if code != 0:
            failures.append("baseline desensitization gate is not green")
            print(output)

    for name, mutate, expect in LAYOUT_MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="certledger-mut-") as tmp:
            work = Path(tmp) / "w"
            copy_tree(work)
            try:
                mutate(work)
            except AssertionError as error:
                failures.append(f"{name}: mutation could not be applied ({error})")
                print(f"FAIL  {name}: {error}")
                continue
            code, output = run_gate(work, LAYOUT)
            hit = f"FAIL  {expect}" in output
            ok = code == 1 and hit
            print(f"{'ok  ' if ok else 'FAIL'}  {name} → rc={code} expect={expect} hit={hit}")
            if not ok:
                failures.append(f"{name}: rc={code} hit={hit}")
                print(output)

    for name, mutate in DESENS_MUTATIONS:
        with tempfile.TemporaryDirectory(prefix="certledger-mut-") as tmp:
            work = Path(tmp) / "w"
            copy_tree(work)
            try:
                mutate(work)
            except AssertionError as error:
                failures.append(f"{name}: mutation could not be applied ({error})")
                print(f"FAIL  {name}: {error}")
                continue
            code, output = run_gate(work, DESENS)
            ok = code == 1 and "FAIL  " in output
            print(f"{'ok  ' if ok else 'FAIL'}  {name} → rc={code}")
            if not ok:
                failures.append(f"{name}: rc={code}")
                print(output)

    print()
    if failures:
        print(f"结论: {len(failures)} 项未按预期变红")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"结论: 基线全绿 + {len(LAYOUT_MUTATIONS)} 组布局变异 + {len(DESENS_MUTATIONS)} 组脱敏变异 全部按预期变红")
    return 0


if __name__ == "__main__":
    sys.exit(main())
