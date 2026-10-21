"""Orchestration: one command's pipeline, stages passing in-memory objects only.

Layering puts this module above every analysis module and below ``cli`` (``plan/02``
§一), and ``report`` is where that matters. One ``report`` run has to read the
machine **once** and then both judge and render what it read:

    inventory.build  →  hygiene.evaluate  →  render.render

The ledger travels as a dict, in memory, and is handed to ``hygiene`` instead of
being rebuilt there. Rebuilding it would be two reads of one machine: slower, and
— the reason it is not merely slower — capable of describing two *different*
machines in one report, since a container that opened for the ledger can fail to
open thirty milliseconds later. The same rule is why ``render`` receives the
findings document rather than producing it: the judgement happens exactly once,
in exactly one module, and both output formats describe that one result.

Two commands and no more live here. Anything that could be a function of one
stage belongs in that stage; anything that decides what a stage means belongs in
the policy file.
"""

from __future__ import annotations

from typing import Iterable

from certledger.errors import CliError


def report(
    *,
    roots: Iterable[str],
    files: Iterable[str],
    inventory_path: str | None,
    as_of,
    policy,
    json_path: str | None,
    markdown_path: str | None,
    baseline: str | None,
    fail_on: str | None,
    top: int | None,
    redact: bool,
    source: str,
) -> int:
    """Run ``certledger report`` and return its exit code (0/1/2).

    ``2`` is raised as :class:`CliError` so ``cli.main`` produces it from one
    place; ``0`` and ``1`` are decided by the ``--fail-on`` threshold inside the
    renderer, which is the only module that knows what a severity is for.
    """
    if policy is None:
        raise CliError("策略缺失", "report 需要已加载的策略文件（阈值不设代码默认值）")
    if as_of is None:
        raise CliError(
            "--as-of 必填",
            "该工具没有「当前时间」缺省值；请给出 Unix 秒或带时区的 ISO-8601 时刻",
        )

    from certledger.hygiene import evaluate
    from certledger.inventory import build, read_ledger
    from certledger.render import render

    ledger = (
        read_ledger(inventory_path)
        if inventory_path
        else build(
            roots=roots,
            files=files,
            source=source,
            follow_symlinks=None,
            policy=policy,
        )
    )
    findings_document = evaluate(
        roots=(),
        files=(),
        inventory_path=None,
        as_of=as_of,
        policy=policy,
        source=source,
        ledger=ledger,
    )
    return render(
        findings_document=findings_document,
        ledger=ledger,
        policy=policy,
        fail_on=fail_on,
        top=top,
        redact=redact,
        json_path=json_path,
        markdown_path=markdown_path,
        baseline=baseline,
    )


__all__ = ["report"]
