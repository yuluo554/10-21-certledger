#!/usr/bin/env python3
# ═══ 布局门（方法论装订第②件） ═══
# 来源：ai-tool-project-sprint references/templates/check-sprint-layout.mjs（10-19/10-20 共 10 组变异），
#   本文件是同判据集的 Python 重写（项目零 Node 依赖，门必须能被 `python` 直接跑）。
#
# 用法：`python tools/check-sprint-layout.py`
# 退出码：0 全绿 / 1 有 FAIL / 2 用法错误。
#
# 判据一律落**仓库内文件**，不读 git 元数据（浅克隆 / 无 .git 的发布包里 tag、历史深度都会翻转）。
# 每个检查独立 try/except：被检查对象不存在时报一条 FAIL 并继续，不抛栈逃逸。
# 每条判据都配一组变异（tools/selftest-gates.py），**改判据必须同步加变异**。

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CHECKS: list[tuple[str, bool, str]] = []
SCANNED = {"docs": 0, "handoffs": 0, "copies": 0, "doc_tools": 0, "gap_rows": 0, "ledger_rows": 0}


def add(cid: str, ok: bool, detail: str) -> None:
    CHECKS.append((cid, ok, detail))


def read(rel: str) -> str | None:
    path = ROOT / rel
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


# ── 必备件 ────────────────────────────────────────────────────────────────
REQUIRED_FILES = [
    "AGENTS.md",
    "README.md",
    "LICENSE",
    "pyproject.toml",
    ".github/workflows/ci.yml",
    "data/README.md",
    "plan/00-README总览.md",
    "plan/01-题目文档.md",
    "plan/02-架构与技术选型.md",
    "plan/03-模块详设.md",
    "plan/04-数据计划.md",
    "plan/05-里程碑与发布.md",
    "plan/06-交付对标与决策.md",
    "src/certledger/__init__.py",
    "src/certledger/cli.py",
    "src/certledger/data/default-policy.json",
]

# 装订行：三个锚点必须**同现于一行**（顺序无关）。写成 `A.*B.*C` 会把"日期在命令之前"误判为缺。
BINDING_LINE = re.compile(
    r"^>(?=.*ai-tool-project-sprint)(?=.*check-sprint-layout)(?=.*20\d{2}-\d{2}-\d{2}).*$",
    re.MULTILINE,
)

# 必需小节：**锚定到标题行**（`^#{1,4}...关键词`），不是"全文包含关键词"。
# 后者会让"删掉整节但正文提到过这个词"的变异恒绿（假门第一族）。
REQUIRED_SECTIONS = {
    "plan/00-README总览.md": ["文档索引", "决策记录", "承诺-证据台账", "里程碑"],
    "plan/01-题目文档.md": ["任务要求", "评分标准", "边界与非目标"],
    "plan/02-架构与技术选型.md": ["分层", "构建"],
    "plan/04-数据计划.md": ["数据清单", "真值纪律", "数值口径"],
    "plan/05-里程碑与发布.md": ["DoD", "已知未验证项"],
    "plan/06-交付对标与决策.md": ["评分对标", "风险登记"],
    "data/README.md": ["依据查证记录", "数值口径"],
}

# HANDOFF 七节。项目自定更细格式是合法超集：断言"必需节都存在"，不断言"节数恰好等于 7"。
HANDOFF_SECTIONS = ["当前进度", "当前事实", "待办", "既定口径", "环境坑", "DoD", "命令速查"]

# 项目已声明的豁免：M0（骨架）的收尾记录就是计划套件本身，不要求 HANDOFF-M0。
EXEMPT_MILESTONES = (0,)

# 状态副本：同一里程碑在这几处的状态必须互相一致。真值不取自任何单一副本。
STATUS_COPIES = [
    ("plan/00-README总览.md", "里程碑表"),
    ("plan/05-里程碑与发布.md", "状态表"),
    ("README.md", "状态表"),
]

STATUS_LINE = re.compile(r"^\|\s*\*{0,2}M(\d+)\b")
PENDING_MARKERS = ("⬜", "🟡", "未开始", "未执行", "待执行", "待确认")

RELEASE_MILESTONE = 6


def check_required_files() -> None:
    missing = [rel for rel in REQUIRED_FILES if not (ROOT / rel).is_file()]
    SCANNED["docs"] = len(REQUIRED_FILES) - len(missing)
    add(
        "LAYOUT.FILES",
        not missing,
        f"缺: {','.join(missing)}" if missing else f"{SCANNED['docs']} 份必备件齐备",
    )


def check_binding_head() -> None:
    text = read("plan/00-README总览.md") or ""
    ok = bool(BINDING_LINE.search(text))
    add(
        "LAYOUT.BINDING_HEAD",
        ok,
        "plan/00 顶部有装订行（三锚点齐）"
        if ok
        else "plan/00 顶部缺装订行（需同现：方法论名 + 布局门命令 + 装订日期）",
    )


def check_sections() -> None:
    bad: list[str] = []
    for rel, needles in REQUIRED_SECTIONS.items():
        text = read(rel)
        if text is None:
            continue
        missing = [
            needle
            for needle in needles
            if not re.search(r"^#{1,4}[^\n]*" + re.escape(needle), text, re.MULTILINE)
        ]
        if missing:
            bad.append(f"{rel}: {'/'.join(missing)}")
    add(
        "LAYOUT.SECTIONS",
        not bad,
        "；".join(bad) if bad else f"{len(REQUIRED_SECTIONS)} 份文档小节齐备",
    )


def check_documented_tools() -> None:
    """文档点名的 tools/ 脚本必须有实物（被四份文档点名却从未实现的发布门是真实事故形态）。"""
    exempt: set[str] = set()
    plan_dir = ROOT / "plan"
    docs = ["AGENTS.md"]
    if plan_dir.is_dir():
        docs += [f"plan/{p.name}" for p in sorted(plan_dir.glob("*.md"))]
    referenced: set[str] = set()
    for rel in docs:
        text = read(rel)
        if text is None:
            continue
        referenced.update(re.findall(r"tools/[\w.-]+\.(?:py|mjs|js|cjs|sh|ps1)", text))
    if not referenced:
        add("LAYOUT.DOC_TOOLS", False, f"扫了 {len(docs)} 份文档，0 处 tools/ 引用——判据是空的（阳性对照失败）")
        return
    SCANNED["doc_tools"] = len(referenced)
    missing = [rel for rel in sorted(referenced) if rel not in exempt and not (ROOT / rel).is_file()]
    add(
        "LAYOUT.DOC_TOOLS",
        not missing,
        f"文档点名但不存在的工具: {','.join(missing)}"
        if missing
        else f"{SCANNED['doc_tools']} 个文档点名的 tools/ 脚本全部在位",
    )


def tables_with_header(lines: list[str], header_needle: str) -> list[tuple[int, list[str]]]:
    """Every table whose header row contains ``header_needle``.

    Anchoring to the header (not to a row prefix) keeps unrelated tables out of
    the scan: ``plan/05`` also has an "外部依赖" table whose first column is
    ``M1``/``M2``, and a prefix-only matcher reads those rows as milestone
    statuses (false-red family ⑤/⑦).

    Returning **all** such tables matters: ``plan/00`` starts with a document
    index whose header also says 状态, so stopping at the first match would leave
    the milestone table — the copy that actually carries the statuses — unscanned
    (a silent hole, not a red gate).
    """
    found: list[tuple[int, list[str]]] = []
    for i, line in enumerate(lines):
        if not line.startswith("|") or header_needle not in line:
            continue
        rows: list[str] = []
        for row in lines[i + 2 :]:  # +2 skips the header and its separator
            if not row.startswith("|"):
                break
            rows.append(row)
        found.append((i, rows))
    return found


def collect_states() -> dict[int, set[str]]:
    """逐副本采集 `{k: {"done"|"pending"}}`；任一里程碑出现两种状态即 FAIL。"""
    states: dict[int, set[str]] = {}
    SCANNED["copies"] = 0
    for rel, _kind in STATUS_COPIES:
        text = read(rel)
        if text is None:
            continue
        SCANNED["copies"] += 1
        for _header, rows in tables_with_header(text.split("\n"), "状态"):
            for line in rows:
                match = STATUS_LINE.match(line)
                if not match:
                    continue
                pending = any(mark in line for mark in PENDING_MARKERS)
                states.setdefault(int(match.group(1)), set()).add("pending" if pending else "done")
    return states


def check_status(states: dict[int, set[str]]) -> None:
    conflicts = [
        f"M{k} 在副本间状态不一致（{' vs '.join(sorted(values))}）"
        for k, values in sorted(states.items())
        if len(values) > 1
    ]
    add(
        "LAYOUT.STATUS",
        not conflicts,
        "；".join(conflicts)
        if conflicts
        else f"{SCANNED['copies']} 处副本 × {len(states)} 个里程碑 状态全一致",
    )


def check_handoffs(done: list[int]) -> None:
    problems: list[str] = []
    for k in done:
        if k in EXEMPT_MILESTONES:
            continue
        rel = f"plan/HANDOFF-M{k}.md"
        text = read(rel)
        if text is None:
            problems.append(f"{rel}(缺)")
            continue
        SCANNED["handoffs"] += 1
        lack = [needle for needle in HANDOFF_SECTIONS if needle not in text]
        if lack:
            problems.append(f"{rel}(缺节: {'/'.join(lack)})")
    add(
        "LAYOUT.HANDOFFS",
        not problems,
        "；".join(problems)
        if problems
        else f"{SCANNED['handoffs']} 份交接单齐（M0 已声明豁免）",
    )


def check_stale_gaps(done: list[int]) -> None:
    """plan/06 的「缺口」表是状态的隐蔽副本。

    定位方式：找到**表头含「缺口」**的那张表，逐行扫描除首列（编号）以外的所有单元格。
    不只看某一列：真实故障既可能写在"内容"格，也可能写在"关闭条件"格里。
    匹配前先剥掉行内代码与文件路径形态——`plan/RELEASE-M6.md` 这类**文件引用**不是
    状态引用，直接匹配会把"已关闭：见发布留档"判成"仍在提 M6"（假门族 ⑥/⑧）。
    扫描面收窄到"首条非表格行即止"，因为后面章节的表格不是缺口表（假门族 ⑦）。
    行数打进结论：全部关闭时只剩表头，此时"扫了 0 行"必须能与"表头搬家了"区分（⑩）。
    """
    lines = (read("plan/06-交付对标与决策.md") or "").split("\n")
    header = next((i for i, line in enumerate(lines) if line.startswith("|") and "缺口" in line), -1)
    if header < 0:
        add("LAYOUT.GAPS", False, "plan/06 找不到含『缺口』表头的表（判据表搬走了？）")
        return
    stale: list[str] = []
    rows = 0
    for line in lines[header + 2 :]:
        if not line.startswith("|"):
            break
        rows += 1
        cells = line.split("|")[2:-1]  # 去掉首列编号与两侧空串
        for cell in cells:
            cleaned = re.sub(r"`[^`]*`|[\w./-]+\.md", "", cell)
            for k in done:
                if re.search(rf"(^|[^0-9A-Za-z])M{k}([^0-9]|$)", cleaned):
                    stale.append(f"plan/06 缺口表仍提 M{k}: {cell.strip()}")
    SCANNED["gap_rows"] = rows
    add(
        "LAYOUT.GAPS",
        not stale,
        "；".join(stale) if stale else f"plan/06 缺口表扫了 {rows} 行，无已完成的里程碑",
    )


def check_ledger(done: list[int]) -> None:
    """承诺-证据台账是第四份状态副本，且不在"状态表"里（表头定位与别人不同，必须单独一条判据）。"""
    lines = (read("plan/00-README总览.md") or "").split("\n")
    header = next(
        (i for i, line in enumerate(lines) if line.startswith("|") and "承诺" in line and "状态" in line),
        -1,
    )
    if header < 0:
        add("LAYOUT.LEDGER", False, "plan/00 找不到『承诺-证据台账』表头（承诺项与状态列）")
        return
    SCANNED["copies"] += 1
    bad: list[str] = []
    rows = 0
    for line in lines[header + 2 :]:
        if not line.startswith("|"):
            break
        rows += 1
        cells = [c.strip() for c in line.split("|")]
        status = cells[-2] if len(cells) >= 2 else ""
        if not re.search(r"[⬜🟡]|未开始|待 M\d|待开工", status):
            continue
        for k in done:
            if re.search(rf"(^|[^0-9A-Za-z])M{k}([^0-9]|$)", status, re.IGNORECASE):
                bad.append(f"台账行仍挂未完成: {status[:60]}")
    SCANNED["ledger_rows"] = rows
    add(
        "LAYOUT.LEDGER",
        not bad and rows > 0,
        f"台账表 0 行——判据空跑"
        if rows == 0
        else ("；".join(bad) if bad else f"台账 {rows} 行，已完成的里程碑无未完成标记"),
    )


def check_release(done: list[int], all_milestones: list[int]) -> None:
    """收尾记录只挂在**发布里程碑**上；未完成时本项 PASS 并写明"尚不适用"。"""
    release = RELEASE_MILESTONE
    if release not in done:
        add(
            "LAYOUT.RELEASE",
            True,
            f"发布里程碑 M{release} 未完成，收尾记录尚不适用（已扫 {len(done)} 个 ✅ 里程碑）",
        )
        return
    text = read(f"plan/RELEASE-M{release}.md") or read(f"plan/WRAPUP-M{release}.md")
    if text is None:
        add("LAYOUT.RELEASE", False, f"缺 plan/RELEASE-M{release}.md 或 plan/WRAPUP-M{release}.md")
        return
    two_columns = bool(re.search(r"^##\s*一、tag 前事实", text, re.M)) and bool(
        re.search(r"^##\s*二、tag 后追加", text, re.M)
    )
    heading = bool(re.search(r"^#{2,3}.*覆盖对账", text, re.M))
    rows = len(re.findall(r"^\|.*(?:实现|不适用|待首推).*\|$", text, re.M))
    add(
        "LAYOUT.RELEASE",
        two_columns and heading and rows >= 3,
        f"两栏:{two_columns} 覆盖对账小节:{heading} 三态行数:{rows}",
    )


def check_ci_step() -> None:
    """门的 CI 接线本身要可断言：两条门命令必须出现在 workflow 里。"""
    text = read(".github/workflows/ci.yml") or ""
    needles = ["tools/check-sprint-layout.py", "tools/check-desensitized.py"]
    missing = [n for n in needles if n not in text]
    add(
        "LAYOUT.CI_STEP",
        not missing,
        f"ci.yml 缺步骤: {','.join(missing)}" if missing else "两条门命令都在 ci.yml 里",
    )


def main() -> int:
    if len(sys.argv) > 1:
        sys.stderr.write("check-sprint-layout: 不接受参数\n")
        return 2

    simple = (
        check_required_files,
        check_binding_head,
        check_sections,
        check_documented_tools,
        check_ci_step,
    )
    for run in simple:
        try:
            run()
        except Exception as error:  # noqa: BLE001 - 门永不崩
            add(run.__name__, False, f"检查异常: {error}")

    states: dict[int, set[str]] = {}
    try:
        states = collect_states()
    except Exception as error:  # noqa: BLE001
        add("LAYOUT.STATUS", False, f"状态采集异常: {error}")

    done = sorted(k for k, values in states.items() if "done" in values)
    all_milestones = sorted(states)
    late = (
        lambda: check_status(states),
        lambda: check_handoffs(done),
        lambda: check_stale_gaps(done),
        lambda: check_ledger(done),
        lambda: check_release(done, all_milestones),
    )
    names = ("check_status", "check_handoffs", "check_stale_gaps", "check_ledger", "check_release")
    for name, run in zip(names, late):
        try:
            run()
        except Exception as error:  # noqa: BLE001
            add(name, False, f"检查异常: {error}")

    failed = [c for c in CHECKS if not c[1]]
    out = ["布局门（方法论装订） · 判据只落仓库内文件", "=" * 56]
    for cid, ok, detail in CHECKS:
        out.append(f"{'PASS' if ok else 'FAIL'}  {cid}  {detail}")
    out.append("=" * 56)
    out.append(
        "这轮扫到：文档 {docs} / 交接单 {handoffs} / 状态副本 {copies} / "
        "文档点名工具 {doc_tools} / 缺口行 {gap_rows} / 台账行 {ledger_rows}".format(**SCANNED)
    )
    out.append(f"结论: {'全绿' if not failed else f'{len(failed)} 项 FAIL'}")
    sys.stdout.write("\n".join(out) + "\n")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
