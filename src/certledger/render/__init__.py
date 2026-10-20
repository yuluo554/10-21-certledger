"""Report rendering: JSON + Markdown from one in-memory model (not implemented yet).

Rendering performs no judgement (plan/03 §④): it must not import
``certledger.hygiene``. Both formats share one sort order so a second run with
the same ``--as-of`` is byte-identical.
"""

from __future__ import annotations

from typing import Iterable


def render(
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
    raise NotImplementedError("render.render 尚未实现")
